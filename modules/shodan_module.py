import os
import shodan
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../configs/api_keys.env'))
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

api = shodan.Shodan(SHODAN_API_KEY)

def shodan_host_info(ip: str) -> str:
    try:
        result = api.host(ip)
        output = [
            f"🌐 Shodan Report for {ip}",
            f"- Organization: {result.get('org', 'N/A')}",
            f"- Operating System: {result.get('os', 'N/A')}",
            f"- Country: {result.get('country_name', 'N/A')}",
            f"- ISP: {result.get('isp', 'N/A')}",
            f"- Open Ports: {', '.join(str(p) for p in result.get('ports', []))}",
            "\n🔧 Service Info:"
        ]
        for item in result['data']:
            port = item['port']
            banner = item.get('banner', 'No banner')
            output.append(f"  - Port {port}: {banner[:100]}...")  # Limit to 100 chars
        return "\n".join(output)
    except shodan.APIError as e:
        return f"🚫 Shodan API error: {e}"
