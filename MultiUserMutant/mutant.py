import httpx
import json
import asyncio
import os
from typing import List, Dict
from openai import AsyncOpenAI
from playwright.async_api import async_playwright
from scorer import AnomalyScorer
from authlib.jose import jwt
from openapi_schema_pydantic import OpenAPI

class MultiUserMutant:
    def __init__(self, spec_url: str):
        self.spec_url = spec_url
        self.client = httpx.AsyncClient(timeout=10.0)
        self.workflows = []
        self.spec_data = {}
        self.scorer = AnomalyScorer()
        self.llm_client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY", "dummy_key"))

    def generate_dummy_token(self, role: str) -> str:
        # Example authlib usage
        header = {'alg': 'HS256'}
        payload = {'iss': 'MultiUserMutant', 'sub': 'test', 'role': role}
        return jwt.encode(header, payload, b'secret').decode('utf-8')

    async def fetch_spec(self):
        try:
            resp = await self.client.get(self.spec_url)
            self.spec_data = resp.json()
            print(f"Fetched target spec from {self.spec_url}: {resp.status_code}")
        except Exception as e:
            print(f"Spec fetch failed: {e}")
            # Mock PortSwigger schema for testing when external fetch fails
            self.spec_data = {
                "openapi": "3.0.0",
                "info": {"title": "PortSwigger Mock API", "version": "1.0.0"},
                "paths": {
                    "/api/v1/user/account": {
                        "get": {"responses": {"200": {"description": "OK"}}},
                        "post": {"responses": {"200": {"description": "Updated"}}}
                    }
                }
            }

    async def generate_hypotheses(self):
        print("Analyzing OpenAPI spec via LLM to generate attack workflows...")
        
        # Openapi-schema-pydantic validation check (example integration)
        try:
            openapi_model = OpenAPI.model_validate(self.spec_data)
            schema_str = openapi_model.model_dump_json(exclude_unset=True)[:2000]
        except Exception:
            schema_str = json.dumps(self.spec_data)[:2000]
        
        try:
            with open("prompts.md", "r") as f:
                system_prompt = f.read()
                
            prompt = system_prompt.replace("[spec]", schema_str)
            
            response = await self.llm_client.chat.completions.create(
                model="gpt-4-turbo-preview",
                messages=[
                    {"role": "system", "content": "You are a security researcher generating raw JSON array of workflows."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            
            content = response.choices[0].message.content
            parsed = json.loads(content)
            if "workflows" in parsed:
                self.workflows = parsed["workflows"]
            elif isinstance(parsed, list):
                self.workflows = parsed
            else:
                self.workflows = [parsed]
                
        except Exception as e:
            print(f"LLM generation failed (likely due to missing OPENAI_API_KEY). Falling back to basic testing. Error: {e}")
            self.workflows = [
                {
                    "id": "mutant-01-idor",
                    "setup_role": "admin",
                    "setup_req": {"method": "POST", "path": "/api/users", "data": {"name": "target_user", "job": "leader"}},
                    "exploit_role": "standard",
                    "exploit_req": {"method": "PUT", "path": "/api/users/2", "data": {"name": "hacked", "job": "pwned"}}
                }
            ]
        return self.workflows

    async def execute_workflow_httpx(self, workflow: Dict, base_url: str):
        setup = workflow.get("setup_req", {})
        setup_role = workflow.get("setup_role", "standard")
        setup_headers = {"Authorization": f"Bearer {self.generate_dummy_token(setup_role)}"}
        
        try:
            if setup.get("method") == "POST":
                await self.client.post(f"{base_url}{setup.get('path')}", json=setup.get("data"), headers=setup_headers)
            elif setup.get("method") == "GET":
                await self.client.get(f"{base_url}{setup.get('path')}", headers=setup_headers)
        except Exception:
            pass

        exploit = workflow.get("exploit_req", {})
        exploit_role = workflow.get("exploit_role", "anonymous")
        exploit_headers = {"Authorization": f"Bearer {self.generate_dummy_token(exploit_role)}"}
        
        try:
            if exploit.get("method") == "PUT":
                res2 = await self.client.put(f"{base_url}{exploit.get('path')}", json=exploit.get("data"), headers=exploit_headers)
            elif exploit.get("method") == "DELETE":
                res2 = await self.client.delete(f"{base_url}{exploit.get('path')}", headers=exploit_headers)
            else:
                res2 = await self.client.get(f"{base_url}{exploit.get('path')}", headers=exploit_headers)
                
            return {
                "workflow_id": workflow.get("id"),
                "status_code": res2.status_code,
                "body_len": len(res2.text),
                "success": res2.status_code in [200, 201, 204]
            }
        except Exception as e:
            return {"workflow_id": workflow.get("id"), "status_code": 0, "error": str(e), "success": False}

    async def execute_workflow_playwright(self, workflow: Dict, base_url: str):
        # Optional execution path via Playwright to handle complex client-side states
        print(f"Running workflow via Playwright: {workflow.get('id', 'unknown')}")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                exploit = workflow.get("exploit_req", {})
                
                # We simulate navigating to an endpoint with the browser to test auth boundaries
                response = await page.goto(f"{base_url}{exploit.get('path')}")
                status = response.status if response else 0
                body = await response.body() if response else b""
                
                await browser.close()
                return {
                    "workflow_id": workflow.get("id") + "-pw",
                    "status_code": status,
                    "body_len": len(body),
                    "success": status in [200, 201, 204]
                }
        except Exception as e:
            return {"workflow_id": workflow.get("id") + "-pw", "status_code": 0, "error": str(e), "success": False}

    async def run_loop(self, base_url: str, iterations: int = 100):
        await self.fetch_spec()
        
        for i in range(iterations):
            print(f"\\n--- Iteration {i+1}/{iterations} ---")
            await self.generate_hypotheses()
            
            results = []
            for wf in self.workflows:
                res = await self.execute_workflow_httpx(wf, base_url)
                results.append(res)
            
            # Score results
            scored_results = self.scorer.score_batch(results)
            
            highest_score = scored_results[0].get("vuln_score", 0) if scored_results else 0
            print(f"Top Score this iteration: {highest_score}")
            for sr in scored_results:
                if sr.get("vuln_score", 0) > 0:
                    print(f"Flagged Vuln: {sr}")
            
            if highest_score == 0:
                print("No critical vulnerabilities detected in this generation. Evolving loop...")
                # In a full run, we would feed the scorer feedback back into the LLM prompt.
                
            # Break early for demo purposes after 2 iterations to prevent long runtimes
            if i >= 1:
                break
                
        return results

    async def cleanup(self):
        await self.client.aclose()

if __name__ == "__main__":
    async def main():
        # Target PortSwigger API labs mock or known JSON
        base_url = "https://portswigger-labs.net/api"
        mutant = MultiUserMutant(spec_url=f"{base_url}/openapi.json")
        
        # Run 100-iteration loop (demo stops early)
        await mutant.run_loop(base_url, iterations=100)
            
        await mutant.cleanup()
        
    asyncio.run(main())
