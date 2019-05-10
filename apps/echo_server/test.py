from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
import time

def run_test():
	print "Running echo server test..."
	chrome_options = Options()
	chrome_options.add_argument("--headless")
	
	driver = webdriver.Chrome(chrome_options = chrome_options)
	driver.get("http://localhost:8000/echo_server/")
	time.sleep(10)	
	log = driver.find_element_by_id("log")
	print log.text
	print "Test finished"	
	driver.quit()

if __name__ == "__main__":
	run_test()
