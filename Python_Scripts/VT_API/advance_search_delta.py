import os
import asyncio
import httpx
import re
from typing import List, Dict

# --- Configuration ---
API_KEY = os.environ.get('GTI_APIKEY')
BASE_URL = "https://www.virustotal.com/api/v3/intelligence/search"
# Enterprise keys handle high concurrency; 10-20 is safe for a local PC
CONCURRENCY_LIMIT = 10 

async def fetch_gti_metadata(client: httpx.AsyncClient, query: str, semaphore: asyncio.Semaphore) -> Dict:
    """
    Retrieves metadata for a query. Optimized for 10M+ datasets.
    """
    async with semaphore:
        # limit=1 ensures we get the 'meta' object with minimum bandwidth
        params = {'query': query, 'limit': 1, 'descriptors_only': True}
        headers = {'Accept': 'application/json', 'x-apikey': API_KEY}
        
        try:
            response = await client.get(BASE_URL, params=params, headers=headers, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            
            meta = data.get('meta', {})
            return {
                "query": query,
                "total": meta.get('total_hits', 0),
                "is_estimated": meta.get('estimated_total_hits', False),
                "error": None
            }
        except Exception as e:
            return {"query": query, "total": 0, "is_estimated": False, "error": str(e)}

def calculate_delta(q1_total: int, current_total: int) -> str:
    if q1_total == 0:
        return "N/A"
    delta_pct = ((current_total - q1_total) / q1_total) * 100
    return f"{delta_pct:+.2f}%"

async def run_analysis(queries: List[str]):
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    async with httpx.AsyncClient() as client:
        tasks = [fetch_gti_metadata(client, q, semaphore) for q in queries]
        results = await asyncio.gather(*tasks)

        # --- Table UI ---
        header = f"{'Label':<10} | {'Query (Truncated)':<50} | {'Hits':<15} | {'Delta (%)':<10}"
        divider = "=" * len(header)
        print(f"\n{header}\n{divider}")

        q1_hits = results[0]['total']
        
        for i, res in enumerate(results):
            label = f"Query {i+1}"
            
            if res['error']:
                hit_str = "ERROR"
                delta_str = "---"
            else:
                # Requirement: Show ~ prefix if the GTI meta indicates an estimate
                est_prefix = "~" if res['is_estimated'] else ""
                hit_str = f"{est_prefix}{res['total']:,}"
                delta_str = "---" if i == 0 else calculate_delta(q1_hits, res['total'])

            display_q = (res['query'][:47] + "...") if len(res['query']) > 50 else res['query']
            print(f"{label:<10} | {display_q:<50} | {hit_str:<15} | {delta_str:<10}")

def main():
    if not API_KEY:
        print("Error: GTI_APIKEY not found in environment variables.")
        return

    print("Enter GTI queries separated by '|' (e.g., Query1 | Query2 | Query3)")
    user_input = input("\n> ")
    query_list = [q.strip() for q in user_input.split('|') if q.strip()]

    if not query_list:
        print("No queries provided.")
        return

    asyncio.run(run_analysis(query_list))

if __name__ == "__main__":
    main()