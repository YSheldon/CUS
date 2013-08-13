#!/usr/bin/env python
#coding:utf-8
# Author:  GreySign --<KnownSec>
# Purpose: 
#         Decode Ascii Numbers From Hex（16进制）、 Octal（八进制）、 Decimal（10进制）
#         Escape Decode
# Created: 2010/12/6

import sys
import re
from urllib import unquote

########################################################################
class DecodeEscape(object):
	""""""

	#----------------------------------------------------------------------
	def __init__(self):
		"""Constructor"""
		pass
	
	#----------------------------------------------------------------------
	def unescape(self,data):
		""""""
		if '%' not in data:
			return data
		return unquote(data)
		
	#----------------------------------------------------------------------
	def _test(self):
		""""""
		data = '%3C%73%63%72%69%70%74%20%6C%61%6E%67%75%61%67%65%3D%76%62%73%63%72%69%70%74%3E'
		print self.unescape(data)
    
	
########################################################################
class DecodeUSAsciiCode:
	""""""

	#----------------------------------------------------------------------
	def __init__(self):
		"""Constructor"""
		pass

	def get_att_value(self,html,tag,att_name):
		"""获取指定tag与属性名的值列表"""
		tag_start = '<' + tag
		if tag_start not in html:
			return []
		values = []
		tag_content_pattern = r"""<%s([^>]+)>"""%tag
		tag_content_reobj = re.compile(tag_content_pattern,  re.IGNORECASE)
		tag_contents = tag_content_reobj.findall(html)
		tag_value_pattern = r"""\b%s\s*=\s*(?:[\\]?"([^"]*?)[\\]?"|[\\]?'([^']*?)[\\]?'|([^>'"\s]+))"""%att_name
		tag_value_reobj = re.compile(tag_value_pattern,re.IGNORECASE)
		if tag_contents != []:
			for content in tag_contents:
				value = tag_value_reobj.findall(content)
				if value != []:
					for i in value[0]:
						if i != "" and i not in values:
							values.append(i)
			return values
		else:
			return []
	
	#----------------------------------------------------------------------
	def cut_usascii_data(self,data):
		"""
		截取<meta http-equiv="Content-Type" content="text/html; charset=US-ASCII" />之后的数据
		"""
		charset = self.get_att_value(data,'meta','charset')
		if not charset or  charset[0].upper() != 'US-ASCII':
			return ''
		#截取meta标签后的所有数据
		sre_obj = re.search('<meta[^<>]+?>',data)
		end = sre_obj.end()
		data = data[end:]
		return data
			
		
	def conv_data(self,data,is_usascii=False):
		if not is_usascii:
			cut_data = self.cut_usascii_data(data)
			if not cut_data:
				return data
			else:
				data = cut_data
		conved_data = ''
		for char in data:
			conved_data += chr(ord(char) ^ 128)
		return conved_data
	
	#----------------------------------------------------------------------
	def _test(self):
		""""""
		data = file('./test/encodescan/usascii-1.txt').read()
		print self.conv_data(data)
			
	
########################################################################
class DecodeAsciiCode(object):
	"""Decode Ascii Numbers From Hex（16进制）、 Octal（八进制）、 Decimal（10进制）"""

	#----------------------------------------------------------------------
	def __init__(self):
		"""Constructor"""
		pass

	#----------------------------------------------------------------------
	def baseN(num,b):
		'''32进制内转10进制'''
		return ((num == 0) and  "0" ) or ( baseN(num // b, b).lstrip("0") + "0123456789abcdefghijklmnopqrstuvwxyz"[num % b])

	#----------------------------------------------------------------------
	def hex2char(self,data):
		'''转换ascii 16进制的数值为字符'''
		def f(sre_obj):
			try:
				ascii_code = sre_obj.group().replace('\\','').replace('x','')
				ascii_10_code = (int(ascii_code,16))
				char = chr(ascii_10_code)
				return char
			except:
				return ''
		#while re.search(r'((?:\\\\|\\)x[\da-fA-F]+)',data):
		data = re.sub(r'((?:\\\\|\\)x[\da-fA-F]+)',f,data)
		return data
	
	#----------------------------------------------------------------------
	def octal2char(self,data):
		'''转换ascii 8进制的数值为字符'''
		def f(sre_obj):
			try:
				ascii_code = sre_obj.group().replace('\\','')
				ascii_10_code = (int(ascii_code,8))
				char = chr(ascii_10_code)
				return char
			except:
				return ''
		#while re.search(r'((?:\\\\|\\)[\d]+)',data):
		data = re.sub(r'((?:\\\\|\\)[\d]+)',f,data)
		return data

	#----------------------------------------------------------------------
	def decimal2char(self,data):
		'''转换ascii 10进制的数值为字符'''
		def f(sre_obj):
			try:
				ascii_code = sre_obj.group().replace(',','')
				ascii_10_code = (int(ascii_code))
				char = chr(ascii_10_code)
				return char
			except:
				return ''
		ascii_codes = re.findall('(?:[\d]{1,3},){5,}[\d]{1,3}',data)
		decode_data = ''
		for ascii_code in ascii_codes:
			decode_data = re.sub(r'[\d]+,?',f,ascii_code)
			data = data.replace(ascii_code,decode_data)
		return data
	
	#----------------------------------------------------------------------
	def _test(self):
		""""""
		data = file('./test/encodescan/16ascii-1.txt').read()
		print self.hex2char(data)
		data = file('./test/encodescan/8ascii-1.txt').read()
		print self.octal2char(data)
		data = file('./test/encodescan/10ascii-1.txt').read()
		print self.decimal2char(data) 

########################################################################
class SmartDecoder:
	""""""

	#----------------------------------------------------------------------
	def __init__(self):
		"""Constructor"""
		self.dac = DecodeAsciiCode()
		self.de = DecodeEscape()
		self.dusc = DecodeUSAsciiCode()
		
	#----------------------------------------------------------------------
	def decode(self,data):
		""""""
		if not data:
			return ''
		raw_data = data
		#需要进行下次解密的标志
		need_decode = True
		#最多反复解密5次
		for i in xrange(5):
			#不需要再度解密就退出
			if not need_decode:
				break
			need_decode = False
			#16进制数据
			if re.search(r'((?:\\\\|\\)x[\da-fA-F]+)',data):
				data = self.dac.hex2char(data)
				need_decode = True
			#8进制数据
			if re.search(r'((?:\\\\|\\)[\d]+)',data):
				data = self.dac.octal2char(data)
				need_decode = True
			#10进制数据
			if re.search('(?:[\d]{1,3},){5,}[\d]{1,3}',data):
				data = self.dac.decimal2char(data)
				need_decode = True
			#escape数据
			if re.search(r'''\%[\da-fA-F]{2}''',data):
				data = self.de.unescape(data)
				need_decode = True
			#US-ASCII数据
			if self.dusc.cut_usascii_data(data):
				data = self.dusc.conv_data(data)
				need_decode = True
		return data
			
		
	#----------------------------------------------------------------------
	def _test(self):
		""""""
		#data = file('./test/encodescan/16ascii-1.txt').read()
		#print self.decode(data)
		#data = file('./test/encodescan/8ascii-1.txt').read()
		#print self.decode(data)
		#data = file('./test/encodescan/10ascii-1.txt').read()
		#print self.decode(data) 
		#data = file('./test/encodescan/escape-1.txt').read()
		#print self.decode(data)
		#data = file('./test/encodescan/escape-2.txt').read()
		#print self.decode(data)
		#data = file('./test/expscan/08053-1.txt').read()
		#print self.decode(data)
		#data = file('./test/encodescan/usascii-1.txt').read()
		data = file('./test/encodescan/16ascii-2.txt').read()
		print self.decode(data)
		

if __name__=='__main__':
	d = DecodeAsciiCode()
	#d._test()
	d2 = DecodeEscape()
	#d2._test()
	dusc = DecodeUSAsciiCode()
	#dusc._test()
	sd = SmartDecoder()
	sd._test()