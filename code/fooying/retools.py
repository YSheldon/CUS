#!/usr/bin/env python
#coding:utf-8
# Author:  GreySign
# Purpose: 正则匹配工具包
# Created: 2011/03/13
# Update:  2012/3/13
VERSION = 1.1
# History:
"""
2012/3/13:
           1.修改获取标签正文的接口，改为获取所有标签正文返回列表
2012/3/15:
           1.分类规划为：正则自动生成、ascii编码处理、实体符编码处理、HTML标签处理、格式校验、文本提取、代码混淆处理
           2.新增ascii编码处理能力，可处理8、10、16进制ascii编码、escape编码自动递归多次解密
           3.新增实体符编码处理能力，可处理16进制、10进制的编码实体符转换
           4.新增自动生成长正则能力
           5.新增代码混淆处理能力，可处理字符串拼接问题
2012/5/31:
		   1.新增url格式校验

2012/6/5:
		   1.新增从url获取目录的接口
2012/6/7:
		   1.新增从html获取所有同域名的相对目录的接口：get_html_dirs
2012/6/12:
		   1.修复域名、url格式识别大小写没处理的bug
		   2.新增识别内网ip地址段格式
"""
import re
import trie,decoder
import urllib,urlparse
import pdb


__all__ = ['www']


########################################################################
class FormatError(Exception):
	""""""
	pass


########################################################################
class WWW(object):
	"""
	关于WEB的那些匹配处理和格式化处理
	1.is_xxxx系列：做格式验证
	2.get_xxxx系列：获取特定文本
	"""


	#----------------------------------------------------------------------
	def __init__(self):
		"""Constructor"""
		self.is_funcs = [
			self.is_domain_format,
			self.is_ip_format
		]
		self.get_funcs = [
			self.get_domain,
			self.get_rootdomain,
			self.get_tag_att_value,
			self.get_tag_content
		]
		self.trie = trie.Trie()
		self.decoder = decoder.SmartDecoder()

		self.init_suffix()

	def init_suffix(self):

		self.domain_suffixs = (
		    '.com','.net','.org','.cn','.info','.name',
		    #把常见域名放前面,提高"短路"几率来提高性能,非常见域名按字母顺序,便于维护
		    '.ac','.ad','.ae','.aero','.af','.ag','.ai','.al','.am','.an',
		    '.ao','.aq','.ar','.arpa','.as','.asia','.at','.au','.aw','.ax',
		    '.az','.ba','.bb','.bd','.be','.bf','.bg','.bh','.bi','.biz',
		    '.bj','.bm','.bn','.bo','.br','.bs','.bt','.bv','.bw','.by',
		    '.bz','.ca','.cat','.cc','.cd','.cf','.cg','.ch','.ci','.ck',
		    '.cl','.cm','.co','.coop','.cr','.cu','.cv','.cw',
		    '.cx','.cy','.cz','.de','.dj','.dk','.dm','.do','.dz','.ec',
		    '.edu','.ee','.eg','.er','.es','.et','.eu','.fi','.fj','.fk',
		    '.fm','.fo','.fr','.ga','.gb','.gd','.ge','.gf','.gg','.gh',
		    '.gi','.gl','.gm','.gn','.gov','.gp','.gq','.gr','.gs','.gt',
		    '.gu','.gw','.gy','.hk','.hm','.hn','.hr','.ht','.hu','.id',
		    '.ie','.il','.im','.in','.int','.io','.iq','.ir','.is',
		    '.it','.je','.jm','.jo','.jobs','.jp','.ke','.kg','.kh','.ki',
		    '.km','.kn','.kp','.kr','.kw','.ky','.kz','.la','.lb','.lc',
		    '.li','.lk','.lr','.ls','.lt','.lu','.lv','.ly','.ma','.mc',
		    '.md','.me','.mg','.mh','.mil','.mk','.ml','.mm','.mn','.mo',
		    '.mobi','.mp','.mq','.mr','.ms','.mt','.mu','.museum','.mv','.mw',
		    '.mx','.my','.mz','.na','.nc','.ne','.nf','.ng',
		    '.ni','.nl','.no','.np','.nr','.nu','.nz','.om','.pa',
		    '.pe','.pf','.pg','.ph','.pk','.pl','.pm','.pn','.post','.pr',
		    '.pro','.ps','.pt','.pw','.py','.qa','.re','.ro','.rs','.ru',
		    '.rw','.sa','.sb','.sc','.sd','.se','.sg','.sh','.si','.sj',
		    '.sk','.sl','.sm','.sn','.so','.sr','.st','.su','.sv','.sx',
		    '.sy','.sz','.tc','.td','.tel','.tf','.tg','.th','.tj','.tk',
		    '.tl','.tm','.tn','.to','.tp','.tr','.travel','.tt','.tv','.tw',
		    '.tz','.ua','.ug','.uk','.us','.uy','.uz','.va','.vc','.ve',
		    '.vg','.vi','.vn','.vu','.wf','.ws','.xxx','.ye','.yt','.za',
		    '.zm','.zw')
		self.domain_suffixs_cn = [
			'.ac.cn','.ah.cn','.bj.cn','.com.cn','.cq.cn','.edu.cn','.fj.cn',
		    '.gd.cn','.gov.cn','.gs.cn','.gx.cn','.gz.cn','.ha.cn','.hb.cn',
		    '.he.cn','.hi.cn','.hk.cn','.hl.cn','.hn.cn','.jl.cn','.js.cn',
			'.jx.cn','.ln.cn','.mo.cn','.net.cn','.nm.cn','.nx.cn',
			'.org.cn','.qh.cn','.sc.cn','.sd.cn','.sh.cn','.sn.cn',
			'.sx.cn','.tj.cn','.tw.cn','.xj.cn','.xz.cn','.yn.cn','.zj.cn'
		]

		self.domain_suffixs_notcn = [
			'.ac.uk', '.ac.za','.alt.za','.biz.ua','.bl.uk','.br.com',
		    '.british-library.uk','.cn.com','.co.at','.co.ca','.co.cm',
		    '.co.im','.co.in','.co.nz','.co.pl','.co.ua','.co.uk','.co.za',
		    '.com.cm','.com.im','.com.mx','.com.ru','.com.tw','.com.uy','.com.vc',
		    '.de.com','.e164.arpa','.edu.cn','.edu.ru','.eu.com','.eu.org',
		    '.fed.us','.firm.in','.gb.com','.gb.net','.gen.in','.gov.uk',
		    '.gov.za','.gr.com','.hu.com','.icnet.uk','.in-addr.arpa','.ind.in',
		    '.jet.uk','.jpn.com','.kr.com','.mod.uk','.net.cc','.net.cm',
		    '.net.in','.net.ru','.net.za','.nhs.uk','.nls.uk','.no.com','.org.in',
		    '.org.ru','.org.za','.parliament.uk','.police.uk','.pp.ua','.priv.at',
		    '.qc.com','.ru.com','.sa.com','.se.com','.se.net','.uk.co','.uk.com',
		    '.uk.net','.us.com','.uy.com','.vicp.net','.web.com','.web.za',
		    '.za.com','.za.net','.za.org'
		]


		self.domain_suffixs_double = tuple(set(['.gov.cn','.com.cn','.net.cn','.org.cn','.com.tw',
			'.com.hk','.me.uk','.org.uk','.ltd.uk','.plc.uk','.com.co','.net.co','.nom.co','.com.ag',
			'.net.ag','.org.ag','.com.bz','.net.bz','.net.br','.com.br','.com.es','.nom.es','.org.es',
			'.co.in','.firm.in','.gen.in','.ind.in','.net.in','.org.in','.com.mx','.co.nz','.net.nz','.org.nz',
			'.org.tw','.idv.tw','.co.uk','.com.com','.com.au','.co.jp','.co.za','.com.ar','.co.kr','.com.ua','.co.il',
			'.co.jp','.com.au','.co.za','.com.ar','.co.kr','.com.ua','.co.il','.com.tr','.com.pl','.or.jp','.co.id','.org.br',
			'.ne.jp','.co.cc','.ac.jp','.com.ve','.ac.in','.com.my','.gov.in','.org.ua','.com.vn','.co.th','.com.sg','.spb.ru',
			'.nic.in','.kiev.ua','.gov.uk','.ac.ir','.gen.tr','.com.pe','.or.kr','.com.pk','.com.de','.at.tc','.it.tc','.com.nu',
			'.cn.ms','.edu.cn','.hk.tc','.ok.to','.net.tc','.net.tf','.at.hm'] + self.domain_suffixs_notcn + self.domain_suffixs_cn))


		self.file_suffixs = (
			'.htm','.asp','.html','.php','.jsp','.shtml',
			'.dhtml','.nsp','.cgi','.xml','.aspx','.css',
			'.mspx','.do','.js','.vbs','.zone','.ch'
		)
		self.black_file_suffixs = (
			'.doc','.xls','.ppt','.docx','.xlsx','.pptx','.pdf',
			'.swf','.flv','.fla','.mp3','.wma','.mpeg','.mp4','.avi','.rm','.rmvb','.mov','.mid',
			'.zip','.rar','.tar','.gz','.exe','.chm','.jar','.iso',
			'.ico','.ani','.jpg','.gif','.bmp','.jpeg','.png'
		)

	####################
	##正则自动生成相关
	####################
	#----------------------------------------------------------------------
	def give_me_regex(self,strings):
		"""
		自动寻找可匹配该字符串的格式验证规则
		in: 字符串
		out: 可匹配成功的规则
		"""
		if not strings:
			return {}
		regexs = {}
		for func in self.is_funcs:
			if func(strings):
				print '[*]`%s` Matched:'%strings,func.func_name
				print getattr(self,func.func_name+'_reg')
				regexs.update( {func:getattr(self,func.func_name+'_reg')})
		return regexs

	#----------------------------------------------------------------------
	def generation_string_regex(self,strings):
		"""
		基于大量格式类似字符串生成一个正则，用于加速匹配用，不用变量大量字符串进行匹配，一个规则搞定
		in : ['foobar', 'foobah']
		out : fooba[rh]
		"""
		self.trie.data = {}
		for w in strings:    #like 'fooxar', 'foozap', 'fooza']:
			self.trie.add(w)
		return self.trie.regexp()

	####################
	##处理字符ascii编码
	####################
	#----------------------------------------------------------------------
	def ascii_decode(self,html):
		"""
		in：html字符串
		out：调用decoder进行各种解码处理，返回解码后的html
		"""
		return self.decoder.decode(html)

	####################
	##处理实体符编码相关
	####################
	def _get_unicode_char(self,char,charset='utf8'):
		""""""
		try:
			char = char.decode(charset)
			s = ''
			s += str(hex(ord(char) >> 8)).replace('0x','')
			s += str(hex(ord(char) & 0xff)).replace('0x','')
			#print repr(s)
			if len(s)==3:
				s= '0'+s
		except:
			return False
		return s


	#----------------------------------------------------------------------
	def gen_html_hex_char(self,char):
		"""
		生成16进制的html实体符
		"""
		unicode_char = self._get_unicode_char(char)
		if not unicode_char:
			return False
		return '&#x' + unicode_char

	#----------------------------------------------------------------------
	def gen_html_decimal_char(self,char):
		"""
		生成10进制的html实体符
		"""
		if not char.isalnum():
			return False
		return '&#' + str(ord(char))



	#----------------------------------------------------------------------
	def _conv_html_decimal_char(self,html_char):
		"""
		对10进制的HTML实体符进行解码
		"""
		html_char = html_char.replace('&#','')
		return chr(int(html_char.lstrip('0')))

	#----------------------------------------------------------------------
	def _conv_html_hex_char(self,html_char):
		"""
		对16进制的HTML实体符进行解码
		"""
		try:
			html_char = html_char.replace('&#x','')
			if not html_char.isalnum():
				return False
			exec("char = u'\u%s'"%html_char)
			char = char.encode('utf8')
		except:
			return False
		return char

	#----------------------------------------------------------------------
	def conv_html_char(self,html_char):
		"""
		对HTML实体符进行解码，支持10、16进制的实体符
		"""
		if html_char.startswith('&#x'):
			return self._conv_html_hex_char(html_char)
		elif html_char.startswith('&#'):
			return self._conv_html_decimal_char(html_char)
		return False



	####################
	##HTML标签处理
	####################
	def get_tag_att_value(self,html,tag):
		"""获取指定tag的属性名与值的字典集合列表
		in：
			"<img src=# onerror=alert(/[code]/) /><img src=# onerror=alert(/[code2]/) />"
		out：
			[{'onerror': 'alert(/[code]/)', 'src': '#'}, {'onerror': 'alert(/[code2]/)', 'src': '#'}]
		"""
		values = []
		def get_tag_value_content():
			tag_value_content_pattern = r"""<%s([^>]+)>"""%tag
			tag_value_contents = re.findall(tag_value_content_pattern,html,re.I)
			return tag_value_contents

		def get_att_name():
			all_att_names = []
			att_pattern = r"""\s\b([\w]+?)\s*="""
			att_pattern_obj = re.compile(att_pattern,re.I)
			for value_content in value_contents:
				if value_content:
					att_names = att_pattern_obj.findall(value_content)
					if att_names:
						all_att_names.append((value_content,att_names))
			return all_att_names

		def get_att_value():
			att_values = []
			for value_content,att_names in all_att_names:
				att_name_value = {}
				for att_name in att_names:
					tag_value_pattern = r"""
									  \b%s\s*=\s* #属性及赋值符号
									  (?:[\\]?"([^"]*?)[\\]?" #双引号情况，或者是……
									  |
									  [\\]?'([^']*?)[\\]?' #单引号情况，或者是……
									  |
									  ([^>'"\s]+) #无引号情况
									  )"""%att_name
					values = re.findall(tag_value_pattern,value_content,re.I+re.X)
					if values == []:
						continue
					for value in values[0]:
						if not value:
							continue
						if value != "" :
							att_name_value[att_name] = value
				att_values.append(att_name_value)
			return att_values
		value_contents = get_tag_value_content()
		all_att_names = get_att_name()
		att_values = get_att_value()
		return att_values

	def get_tag_content(self,html,tag_name):
		'''
		获取指定标签正文
		in : <script>alert(/[code]/)</script>
		out: ['alert(/[code]/)']
		'''
		html = html.lower()
		if '<%s'%tag_name not in html:
			return []
		regex = r"""<%(tag_name)s[^>]*?>(.*?)</%(tag_name)s>"""%vars()
		compile_obj = re.compile(regex,  re.DOTALL)
		contents = compile_obj.findall(html)
		#if not contents:return []
		'''
		try:
			index = int(index)
			if index < 1:
				index = 1
		except:
			index = 1
		try:
			result = contents[index-1]
		except:
			result = contents[0]
		'''
		return contents

	def get_html_dirs(self,entry,html):
		get_valid_url = self.get_valid_url
		#import pdb;pdb.set_trace()
		#处理frame、iframe、script、a标签的链接

		frame_links = [get_valid_url(self.ascii_decode(atts['src']).strip(),entry) for atts in self.get_tag_att_value(html,'frame') if atts.has_key('src') ]
		iframe_links = [get_valid_url(self.ascii_decode(atts['src']).strip(),entry) for atts in self.get_tag_att_value(html,'frame') if atts.has_key('src') ]
		script_links = [get_valid_url(self.ascii_decode(atts['src']).strip(),entry) for atts in self.get_tag_att_value(html,'script') if atts.has_key('src') ]
		a_links = [get_valid_url(self.ascii_decode(atts['href']).strip(),entry) for atts in self.get_tag_att_value(html,'a') if atts.has_key('href') ]
		links = frame_links + iframe_links + a_links + script_links
		dirs = set()
		for link in links:

			if www.get_domain(link) == www.get_domain(entry):

				rel_dir_url = self.get_urldir(link).replace(entry,'')

				dirs.add(rel_dir_url)
		dirs = list(dirs)
		return dirs

	def check_protocol(self,url):
		"""判断指定url的协议类型"""
		if url.startswith(('javascript:','vbscript:','mailto:','ftp:','mms:','ldap:','about:','data:')):
			return 'PseudoProtocol'
		elif url.startswith(('http://','https://','//','\\/\\/','/\\/\\','http:\\\\','https:\\\\','http:\\/\\/','http:/\\/\\')):
			return 'NormalProtocol'
		otherProtocol = urlparse.urlparse(url)[0]
		if otherProtocol != '':
			return 'OtherProtocol'


	def get_valid_url(self,suburl, parent_url):
		"""
		处理相对路径、绝对路径
		处理不正确的协议
		返回一个有效的绝对路径url
		"""
		get_formed_url = self.get_formed_url
		suburl = suburl.split('#')[0]
		if suburl.strip() == '':
			return ''
		suburl = urllib.quote(suburl,':/\=?,;&#%')
		lowerUrl = suburl.lower()
		if lowerUrl in ('http://','https://','//','\\/\\/','/\\/\\','http:\\\\','https:\\\\','http:\\/\\/','http:/\\/\\'):
			return ''
		whatProtocol = self.check_protocol(lowerUrl)
		if whatProtocol == 'PseudoProtocol':
			return ''
		if whatProtocol == 'OtherProtocol':
			return ''
		if whatProtocol == 'NormalProtocol':
			if lowerUrl.startswith('//'):
				##fix bug:处理//:这种url
				if len(lowerUrl[2:]) <= 5 or '.' in lowerUrl or not lowerUrl.startswith('.') or not lowerUrl.endswith('.'):
					return ''
				suburl = 'http:' + suburl
				suburl = get_formed_url(suburl)
				return suburl
			if lowerUrl.startswith(('\\/\\/','/\\/\\')):
				suburl = 'http:' + suburl.replace('\\','')
				suburl = get_formed_url(suburl)
				return suburl
			if lowerUrl.startswith(('http:\\/\\/','http:/\\/\\')):
				suburl = suburl.replace('\\','')
				suburl = get_formed_url(suburl)
				return suburl
			suburl = suburl.replace('\\\\','//')
			suburl = get_formed_url(suburl)
			return suburl
		urlDir = self.get_urldir(parent_url)
		# python2.5.x urlparse.urljoin bug fixed by cosine 2011/1/10
		# urlparse.urljoin('http://192.168.10.205/aspcheck.asp','?T=HI')
		# python2.5.x输出http://192.168.10.205/?T=HI
		# python2.6.x输出http://192.168.10.205/aspcheck.asp?T=HI
		if suburl.startswith('?'):
			parent_url = parent_url.split('?')[0]
			suburl = parent_url+suburl
			suburl = get_formed_url(suburl)
			return suburl
		suburl = urlparse.urljoin(urlDir, suburl)
		suburl = get_formed_url(suburl)
		return suburl

	def add_protocal(self,url):
		"""格式化：添加协议头"""
		if not url.lower().startswith(('http://','https://')):
			return 'http://'+url
		return url

	def get_siteurl(self,url):
		"""获取指定url的siteurl格式：http://www.knownsec.com"""
		domain = self.get_domain(url)
		if self.is_https(url):
			siteurl = 'https://'+domain
		else:
			siteurl = 'http://'+domain
		return siteurl

	def is_https(self,url):
		"""判断指定url是否是https协议"""
		url = url.lower()
		if url.startswith('https://'):
			return True
		else:
			return False


	def get_formed_url(self,url):
		"""获取规范化的url"""
		url = self.add_protocal(url) # 统一添加http协议
		# 域名后统一添加/
		if url.endswith(self.domain_suffixs):
			url = url+'/'

		# 去除尾部多余的#字符
		while 1:
			if not url.endswith('#'):
				break
			url = url[:-1]

		# schema+host部分统一小写
		siteurl = self.get_siteurl(url)
		path = url[len(siteurl):]
		url = siteurl+path

		return self.traverse_dir_join(url)

	def traverse_dir_join(self,url):
		"""去除url里不合法的目录穿越../../
		http://q.com/../web => http://q.com/web
		http://q.com/x/../../web => http://q.com/web
		http://q.com/x/y/z/.. => http://q.com/x/y
		否则urllib2.urlopen请求会出现403/400等错误！eg: www.knownsec.com
		"""
		if url.lower().startswith(('http://','https://')):
			siteurl = '/'.join(url.split('/')[:3])+'/'
			url = '/'.join(url.split('/')[3:])
		else:
			siteurl = ''

		#url = url.lstrip('../') # 不是去除整个../字符串，而是逐个字符
		while url.startswith('../'):
			url = url[3:]
		uspilits = url.split('/')

		while_loop = True
		while while_loop:
			for_break = False
			ulen = len(uspilits)
			if not ulen:
				break
			for i in xrange(ulen):
				item = uspilits[i]
				if i == 0 and item == '..':
					uspilits.pop(i)
					for_break = True
					break
				if item == '..':
					uspilits.pop(i)
					uspilits.pop(i-1)
					for_break = True
					break
			if not for_break:
				while_loop = False
		url = siteurl + '/'.join(uspilits)
		return url


	####################
	##格式校验
	####################
	def is_legal_port(self,port):
		try:
			if 0 < int(port) <= 65535:
				return True
			return False
		except:
			return False

	#----------------------------------------------------------------------
	def is_ip_format(self,ip_str,only_ip=False):
		"""
		检查IP是否符合格式规范
		默认可以带端口：8.8.8.8:8080
		严格ip格式不允许带端口，使用only_ip=True
		"""
		if not only_ip:
			port_pos = ip_str.find(':')
			#pdb.set_trace()
			if port_pos >= 0 and len(ip_str) > port_pos+1:
				#port not legal
				if not self.is_legal_port(ip_str[port_pos+1:]):
					return False
				ip_str = ip_str[:port_pos]
		if not hasattr(self,'is_ip_format_re_obj'):
			self.is_ip_format_reg = """
                        ^ #必须是串开始
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        $
                    """
			self.is_ip_format_re_obj = re.compile(self.is_ip_format_reg,re.X)
		if self.is_ip_format_re_obj.search(ip_str):
			return True
		else:
			return False

	def is_intra_ip_format(self,ip_str):
		"""
		检查IP是否符合为内网IP地址
		"""
		if not hasattr(self,'is_ip_format_re_obj'):
			self.is_ip_format_reg = """
                    ^ #必须是串开始
					(?:
                        (?: #10.0.0.0  A
                        (?:10)
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        )
						|
                        (?: #172.16.0.0 -- 172.31.0.0 B
                        (?:172)
                        \.
                        (?:1[6-9]|2[0-9]|3[0-1])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        )
						|
                        (?: #192.168.0.0 C
                        (?:192)
                        \.
                        (?:168)
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        \.
                        (?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])
                        )
						|
                        127\.0\.0\.1
					)
					$
                    """
			self.is_ip_format_re_obj = re.compile(self.is_ip_format_reg,re.X)
		if self.is_ip_format_re_obj.search(ip_str):
			return True
		else:
			return False

	def is_url_format(self,url_str):
		"""
		检查URL是否符合格式规范
		支持格式：
			http://<user>:<password>@<host>:<port>/<path>?<searchpart>

		"""
		#import pdb;pdb.set_trace()
		if not hasattr(self,'is_url_format_re_obj'):
			self.is_url_format_reg = """
                        ^ #必须是串开始
                       (?:http(?:s)?://)? #protocol
					   (?:[\w]+(?::[\w]+)?@)? #user@password
					   ([-\w]+\.)+[\w-]+(?:.)? #domain
					   (?::\d{2,5})? #port
					   (/?[-:\w;\./?%&=#]*)? #params
                        $
                    """
			self.is_url_format_re_obj = re.compile(self.is_url_format_reg,re.X|re.I)
		if self.is_url_format_re_obj.search(url_str):
			domain = self.get_domain(url_str)
			print domain
			if not domain:
				return False
			if self.is_domain_format(domain) or self.is_ip_format(re.sub(':\d+','',domain)):
				return True
			else:
				return False
		else:
			return False

	#----------------------------------------------------------------------
	def is_domain_format(self,domain):
		"""
		一个完整的域名，由根域、顶级域、二级、三级……域名构成，每级域名之间用点分开，
		每级域名由字母、数字和减号构成（第一个字母不能是减号），不区分大小写，长度不超过63。
		"""
		if not hasattr(self,'is_domain_format_re_obj'):
			self.is_domain_format_reg = """^(?:https?://)?(?:[A-Za-z0-9\u4E00-\u9FA5-][A-Za-z0-9\u4E00-\u9FA5-]{0,62}\.){1,20}
			(?:(?:aero)|(?:asia)|(?:biz)|(?:cat)|(?:com)|(?:coop)|(?:info)|(?:int)|(?:jobs)|(?:mobi)|(?:museum)|
				(?:name)|(?:net)|(?:org)|(?:pro)|(?:tel)|(?:travel)|(?:xxx)|(?:edu)|(?:gov)|(?:mil)|(?:ac)|(?:ad)|
				(?:ae)|(?:af)|(?:ag)|(?:ai)|(?:al)|(?:am)|(?:an)|(?:ao)|(?:aq)|(?:ar)|(?:as)|(?:at)|(?:au)|(?:aw)|
				(?:ax)|(?:az)|(?:ba)|(?:bb)|(?:bd)|(?:be)|(?:bf)|(?:bg)|(?:bh)|(?:bi)|(?:bj)|(?:bm)|(?:bn)|(?:bo)|
				(?:br)|(?:bs)|(?:bt)|(?:bv)|(?:bw)|(?:by)|(?:bz)|(?:ca)|(?:cc)|(?:cd)|(?:cf)|(?:cg)|(?:ch)|(?:ci)|
				(?:ck)|(?:cl)|(?:cm)|(?:cn)|(?:co)|(?:cr)|(?:cs)|(?:cu)|(?:cv)|(?:cx)|(?:cy)|(?:cz)|(?:dd)|(?:de)|
				(?:dj)|(?:dk)|(?:dm)|(?:do)|(?:dz)|(?:ec)|(?:ee)|(?:eg)|(?:eh)|(?:er)|(?:es)|(?:et)|(?:eu)|(?:fi)|
				(?:fj)|(?:fk)|(?:fm)|(?:fo)|(?:fr)|(?:ga)|(?:gb)|(?:gd)|(?:ge)|(?:gf)|(?:gg)|(?:gh)|(?:gi)|(?:gl)|
				(?:gm)|(?:gn)|(?:gp)|(?:gq)|(?:gr)|(?:gs)|(?:gt)|(?:gu)|(?:gw)|(?:gy)|(?:hk)|(?:hm)|(?:hn)|(?:hr)|
				(?:ht)|(?:hu)|(?:id)|(?:ie)|(?:il)|(?:im)|(?:in)|(?:io)|(?:iq)|(?:ir)|(?:is)|(?:it)|(?:je)|(?:jm)|
				(?:jo)|(?:jp)|(?:ke)|(?:kg)|(?:kh)|(?:ki)|(?:km)|(?:kn)|(?:kp)|(?:kr)|(?:kw)|(?:ky)|(?:kz)|(?:la)|
				(?:lb)|(?:lc)|(?:li)|(?:lk)|(?:lr)|(?:ls)|(?:lt)|(?:lu)|(?:lv)|(?:ly)|(?:ma)|(?:mc)|(?:md)|(?:me)|
				(?:mg)|(?:mh)|(?:mk)|(?:ml)|(?:mm)|(?:mn)|(?:mo)|(?:mp)|(?:mq)|(?:mr)|(?:ms)|(?:mt)|(?:mu)|(?:mv)|
				(?:mw)|(?:mx)|(?:my)|(?:mz)|(?:na)|(?:nc)|(?:ne)|(?:nf)|(?:ng)|(?:ni)|(?:nl)|(?:no)|(?:np)|(?:nr)|
				(?:nu)|(?:nz)|(?:om)|(?:pa)|(?:pe)|(?:pf)|(?:pg)|(?:ph)|(?:pk)|(?:pl)|(?:pm)|(?:pn)|(?:pr)|(?:ps)|
				(?:pt)|(?:pw)|(?:py)|(?:qa)|(?:re)|(?:ro)|(?:rs)|(?:ru)|(?:rw)|(?:sa)|(?:sb)|(?:sc)|(?:sd)|(?:se)|
				(?:sg)|(?:sh)|(?:si)|(?:sj)|(?:sk)|(?:sl)|(?:sm)|(?:sn)|(?:so)|(?:sr)|(?:ss)|(?:st)|(?:su)|(?:sv)|
				(?:sy)|(?:sz)|(?:tc)|(?:td)|(?:tf)|(?:tg)|(?:th)|(?:tj)|(?:tk)|(?:tl)|(?:tm)|(?:tn)|(?:to)|(?:tp)|
				(?:tr)|(?:tt)|(?:tv)|(?:tw)|(?:tz)|(?:ua)|(?:ug)|(?:uk)|(?:us)|(?:uy)|(?:uz)|(?:va)|(?:vc)|(?:ve)|
				(?:vg)|(?:vi)|(?:vn)|(?:vu)|(?:wf)|(?:ws)|(?:ye)|(?:yt)|(?:yu)|(?:za)|(?:zm)|(?:zw)|(?:arpa)|
				(?:gov\.cn)|(?:com\.cn)|(?:net\.cn)|(?:org\.cn)|(?:com\.tw)|(?:com\.hk)|(?:me\.uk)|(?:org\.uk)|
				(?:ltd\.uk)|(?:plc\.uk)|(?:com\.co)|(?:net\.co)|(?:nom\.co)|(?:com\.ag)|(?:net\.ag)|(?:org\.ag)|
				(?:com\.bz)|(?:net\.bz)|(?:net\.br)|(?:com\.br)|(?:com\.es)|(?:nom\.es)|(?:org\.es)|(?:co\.in)|
				(?:firm\.in)|(?:gen\.in)|(?:ind\.in)|(?:net\.in)|(?:org\.in)|(?:com\.mx)|(?:co\.nz)|(?:net\.nz)|
				(?:org\.nz)|(?:org\.tw)|(?:idv\.tw)|(?:co\.uk)|(?:co.jp)|(?:com.au)|(?:co.za)|(?:com.ar)|(?:co.kr)|
				(?:com.ua)|(?:co.il)|(?:com.tr)|(?:com.pl)|(?:or.jp)|(?:co.id)|(?:org.br)|(?:ne.jp)|(?:co.cc)|
				(?:ac.jp)|(?:com.ve)|(?:ac.in)|(?:com.my)|(?:gov.in)|(?:org.ua)|(?:com.vn)|(?:co.th)|(?:com.sg)|
				(?:spb.ru)|(?:nic.in)|(?:kiev.ua)|(?:gov.uk)|(?:ac.ir)|(?:gen.tr)|(?:com.pe)|(?:or.kr)|(?:com.pk)|
				(?:com.de)|(?:at.tc)|(?:it.tc)|(?:com.nu)|(?:cn.ms)|(?:edu.cn)|(?:hk.tc)|(?:ok.to)|(?:net.tc)|
				(?:net.tf)|(?:at.hm))(?:\.)?(?::[\d]{1,5})?$"""
			self.is_domain_format_re_obj = re.compile(self.is_domain_format_reg,re.M|re.I|re.X)
		if self.is_domain_format_re_obj.search(domain):
			return True
		else:
			return False



	####################
	##文本提取
	####################
	def get_domain(self, url):
		"""获取指定url的域名格式：www.knownsec.com"""
		url = url.strip()
		if not url.startswith(('http://','https://')):
			url = 'http://' + url
		url = url.lower()
		head_pos = url.find('//')
		if head_pos != -1:
			url = url[head_pos+2:]
		end_pos = url.find('/')
		if end_pos != -1:
			url = url[:end_pos]
		else:
			end_pos = url.find('?')
			if end_pos != -1:
				url = url[:end_pos]
			else:
				end_pos = url.find('#')
				if end_pos != -1:
					url = url[:end_pos]
		domain = url
		return domain

	def get_rootdomain(self,url):
		"""
		获取指定url的根域名格式：
		www.baidu.com ==> baidu.com
		www.baidu.com.cn ==> baidu.com.cn
		"""
		domain = self.get_domain(url).strip()
		if '%' in domain :
			return False
		domain_list = domain.split('.')
		if domain_list[-1].isdigit():
			return False
		for suffix in self.domain_suffixs_double:
			if domain.endswith(suffix):
				rootDoamin = '.'.join(domain_list[-3:])
				return rootDoamin

		rootDomain = '.'.join(domain_list[-2:])
		return rootDomain


	#----------------------------------------------------------------------
	def get_formated_url(self,url):
		"""
		获取带协议和目录符格式的url。
		示例：
		baidu.com ==> http://baidu.com/
		http://baidu.com ==> http://baidu.com/
		http://baidu.com/1.php ==> http://baidu.com/1.php
		baidu.com/123/ ==> http://baidu.com/123/
		baidu.com/1.php?123 ==> http://baidu.com/1.php?123
		"""
		if not url.startswith('http://') and not url.startswith('https://'):
			url = 'http://' + url
		if url.endswith('/'):
			return url
		if url.replace('://','').find('/') == -1:
			url += '/'
		return url

	def get_urldir(self,url):
		"""
		获取并返回指定url（如：http://www.knownsec.com/hi/mal.html）的目录形式：
		http://www.knownsec.com/hi/
		"""
		lowerUrl = url.lower()
		if url.endswith("/"):
			return url
		if lowerUrl.endswith(self.domain_suffixs) or lowerUrl.endswith(self.domain_suffixs_double):
			return url + '/'
		urlNoParam = lowerUrl.split("?")
		if len(urlNoParam) < 2 and lowerUrl.endswith(self.file_suffixs):
			return url[:url.rindex("/")+1]
		elif urlNoParam[0].endswith(self.file_suffixs):
			return url[:url.rindex("/")+1]
		elif urlNoParam[0].endswith("/"):
			return urlNoParam[0]
		else:
			urlNoParamSem = urlNoParamSem = lowerUrl.split(";")
			if len(urlNoParamSem) > 1:
				if len(urlNoParamSem) < 2 and lowerUrl.endswith(self.file_suffixs):
					return url[:url.rindex("/")+1]
				elif urlNoParamSem[0].endswith(self.file_suffixs):
					return url[:url.rindex("/")+1]
				elif urlNoParamSem[0].endswith("/"):
					return urlNoParamSem[0]
		"""
		TOOD: file_suffixs不完备
		最后不加/了，因为现在每次req后，都会取trueurl，如果是目录自己会加上/
		如果不这样，对于框架式开发的web应用，路径所映射的，根本没目录之说！ by cosine 2012/2/29
		"""
		#return url + "/"
		return url

	def get_split_params(self,url):
		'''
		in：
		'http://translate.google.cn/?hl=zh-CN&tab=wT#123'
		out：
		{'no_params_url':http://translate.google.cn/','params':'hl=zh-CN&tab=wT#123'}
		'''
		try:
			params_start = url.index('?')
		except ValueError:
			params_start =False
		if params_start:
			no_params_url = url[:params_start]
			params = url[params_start+1:]
		else:
			no_params_url = url
			params = ''
		return {'no_params_url':no_params_url,'params':params}

	####################
	##代码混淆还原处理
	####################
	#----------------------------------------------------------------------
	def fix_join_string(self,string):
		""""""
		#fix js字符串拼接
		string = re.sub(r"""["']\s*\+\s*["']""",'',string)
		#fix vbs字符串拼接
		string = re.sub(r"""['"]\s*&\s*['"]""",'',string)
		return string

	#----------------------------------------------------------------------
	def _test(self):
		""""""
		str1 = "<script>alert(/[code]/)</script>"
		str2 = "<img src=# onerror=alert(/[code]/) /><img src=# onerror=alert(/[code2]/) />"
		assert self.get_tag_att_value(str2,'img'),[{'onerror': 'alert(/[code]/)', 'src': '#'}, {'onerror': 'alert(/[code2]/)', 'src': '#'}]
		assert self.get_tag_content(str1,'script'),'alert(/[code]/)'
		if not self.is_domain_format('wcc.cc'):
			raise FormatError,'[!]domain format ERROR!'
		if not self.is_ip_format('10.10.1.1'):
			raise FormatError,'[!]ip format ERROR!'
		print '[*]test ok.'


www = WWW()
if __name__ == '__main__':
	#www._test()
	str2 = "<script>alert(/[code]/)</script><script>123</script>"
	print www.get_tag_content(str2,'script')
	www.give_me_regex('8.8.8.8')
	www.give_me_regex('a.baidu.com')
	print www.generation_string_regex(['foobah','foobar'])
	data = '%3C%73%63%72%69%70%74%20%6C%61%6E%67%75%61%67%65%3D%76%62%73%63%72%69%70%74%3E'
	print www.ascii_decode(data)
	print www._get_unicode_char('a')
	print www.gen_html_decimal_char('a')
	print www.gen_html_hex_char('测')
	print www.conv_html_char('&#x6d4b')
	flower_code = """document.write('<d' + 'iv st' + 'yle' + '="po' + 'si' + 'tio' + 'n:a' + 'bso' + 'lu' + 'te;l' + 'ef' + 't:' + '-' + '11' + '20' + '3' + 'p' + 'x;' + '"' + '>');"""
	print www.fix_join_string(flower_code)
