import requests
import json
import time

API = "http://localhost:8000"

SCENARIOS = [
    "scenario_01_portScan.json",
    "scenario_02_meterpreter.json",
    "scenario_03_c2_beaconing.json",
    "scenario_04_benign_admin.json",
    "scenario_05_hydra_brute.json"
]

def test_static_serving():
    print("Testing static scenario serving...")
    for filename in SCENARIOS:
        url = f"{API}/scenarios/{filename}"
        r = requests.get(url)
        assert r.status_code == 200, f"Failed to fetch {filename}: {r.status_code}"
        print(f"  [OK] {filename} served")

def test_analysis():
    print("\nTesting analysis endpoint with scenarios...")
    for filename in SCENARIOS:
        # Load scenario data
        url = f"{API}/scenarios/{filename}"
        scen_data = requests.get(url).json()
        
        # Analyze
        r = requests.post(f"{API}/predict", json=scen_data)
        assert r.status_code == 200, f"Failed to analyze {filename}: {r.status_code}"
        res = r.json()
        print(f"  [OK] {filename} -> {res.get('threat_level')} (score: {res.get('final_score')})")

if __name__ == "__main__":
    try:
        test_static_serving()
        test_analysis()
        print("\nAll scenario tests PASSED!")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        exit(1)
