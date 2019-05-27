from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
import time
import sys

def run_test():
	print "Running echo server test..."
	chrome_options = Options()
	chrome_options.add_argument("--headless")
	domain = "localhost"
	if len(sys.argv) > 1:
		domain = sys.argv[1]
	driver = webdriver.Chrome(chrome_options = chrome_options)
	driver.get("http://"+domain+":8000/")
	time.sleep(160)
	log = driver.find_element_by_id("log")
	print log.text
	print "Test finished"	
	driver.quit()

if __name__ == "__main__":
	run_test()
