import requests
import re
import json

from tornado import ioloop, httpclient
from engine.core import *
from engine.wordpress import *
from lxml import etree
from multiprocessing import Process, Pool

class Fuzz_Engine:
	def __init__(self, wordpress, fuzz):
		self.theme_vuln_id = []
		self.plugin_vuln_id = []
		if fuzz != False:
			self.fuzzing_component_aggressive(wordpress)
			self.theme_vuln_id = self.fuzzing_themes_aggressive(wordpress)
			self.plugin_vuln_id = self.fuzzing_plugins_aggressive(wordpress)

		self.list_id = self.theme_vuln_id + self.plugin_vuln_id

	"""
	name        : fuzzing_component_aggressive(self, wordpress)
	description : fuzz every component used by the wordpress
	"""
	def fuzzing_component_aggressive(self, wordpress):
		# print notice("Enumerating components from aggressive fuzzing ...")
		print("[+]Enumerating components from aggressive fuzzing ...")

		# Load json file
		with open('fuzz/wordpress.fuzz') as data_file:
			data = data_file.readlines()

			# Run through every component
			global iter_aggressive
			iter_aggressive = 0
			http_client = httpclient.AsyncHTTPClient()

			for component in data:
				component = component.strip()
				iter_aggressive += 1
				http_client.fetch(wordpress.url + component, aggressive_request_component, method='HEAD', validate_cert=False) == True
			ioloop.IOLoop.instance().start()


	"""
	name        : fuzzing_themes_aggressive(self, wordpress)
	description : fuzz every themes used by the wordpress
	"""
	def fuzzing_themes_aggressive(self, wordpress):
		# print notice("Enumerating themes from aggressive fuzzing ...")
		print("[+]Enumerating themes from aggressive fuzzing ...")

		# Load json file
		list_id = []
		with open('fuzz/wp_themes.fuzz') as data_file:
			data = data_file.readlines()

			# Run through every themes
			global iter_aggressive
			iter_aggressive = 0
			http_client = httpclient.AsyncHTTPClient()

			for theme in data:
				theme = theme.strip()
				iter_aggressive += 1
				http_client.fetch(wordpress.url + theme + "style.css", aggressive_request_plugins, method='HEAD', validate_cert=False) == True
			ioloop.IOLoop.instance().start()

		return list_id


	"""
	name        : fuzzing_plugins_aggressive(self, wordpress)
	description : fuzz every plugins used by the wordpress
	"""
	def fuzzing_plugins_aggressive(self, wordpress):
		# print notice("Enumerating plugins from aggressive fuzzing ...")
		print("[+]Enumerating plugins from aggressive fuzzing ...")

		# Load json file
		list_id = []
		with open('fuzz/wp_plugins.fuzz') as data_file:
			data = data_file.readlines()

			# Run through every plugin
			global iter_aggressive
			iter_aggressive = 0
			http_client = httpclient.AsyncHTTPClient()
			for plugin in data:
				plugin = plugin.strip()
				iter_aggressive += 1
				http_client.fetch(wordpress.url + plugin, aggressive_request_plugins, method='HEAD', validate_cert=False) == True
			ioloop.IOLoop.instance().start()
	
		return list_id


def aggressive_request_plugins(response):
	# list_id = []
	if (response.code) == 200:
		display_vulnerable_component(response.effective_url.split('/')[-2], "Unknown", "plugins")

	global iter_aggressive
	iter_aggressive-= 1
	if iter_aggressive == 0:
		ioloop.IOLoop.instance().stop()

	# return list_id

def aggressive_request_themes(response):
	# list_id = []
	if (response.code) == 200:
		display_vulnerable_component(response.effective_url.split('/')[-2], "Unknown", "themes")

	global iter_aggressive
	iter_aggressive-= 1
	if iter_aggressive == 0:
		ioloop.IOLoop.instance().stop()

	# return list_id

def aggressive_request_component(response):
	if (response.code) == 200:
		if "reauth" in response.effective_url:
			print("[i] Authentication Needed: " + response.effective_url+ " - found")
		else:
			print("[i] File: " + response.effective_url+ " - found")

	global iter_aggressive
	iter_aggressive-= 1
	if iter_aggressive == 0:
		ioloop.IOLoop.instance().stop()
