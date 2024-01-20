import requests
from bs4 import BeautifulSoup


def get_website_info(url):
    try:
        response = requests.get(url)

        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            title = soup.title.text if soup.title else 'No Title'
            meta_description = soup.find('meta', attrs={'name': 'description'})
            description = meta_description['content'] if meta_description else 'No Meta Description'

            return {
                'title': title,
                'description': description,
                'url': url
            }
        else:
            print(f"Failed to retrieve content. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


url_to_check = 'http://pageometry.weebly.com'
website_info = get_website_info(url_to_check)

if website_info:
    print("Website Information:")
    for key, value in website_info.items():
        print(f"{key}: {value}")
else:
    print("Failed to retrieve website information.")
