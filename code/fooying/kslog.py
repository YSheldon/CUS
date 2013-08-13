#encoding=utf-8
import logging
import traceback,StringIO

class KSLOG():
	def __init__(self,fn,level=logging.DEBUG):
		logger = logging.getLogger('kslog')
		self.logger = logger
		logger.setLevel(logging.DEBUG)
		fh = logging.FileHandler(fn) 
		fh.setLevel(level)
		ch = logging.StreamHandler() 
		ch.setLevel(level)
		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s') 
		fh.setFormatter(formatter) 
		ch.setFormatter(formatter) 
		if len( logger.handlers) == 0:
			logger.addHandler(fh) 
			logger.addHandler(ch) 
		#print logger.handlers

	def get_err(self):
		s =  traceback.extract_stack()
		fp = StringIO.StringIO()    #创建内存文件对象
		traceback.print_exc(file=fp)
		message = fp.getvalue()
		if message == 'None\n':#取到内容
			return ''
		return message

	def debug(self,info):
		self.logger.debug(info)


	def info(self,info):
		self.logger.info(info)

	def warning(self,info):
		err_info = self.get_err()
		self.logger.warning(info+'\n'+err_info)

	def error(self,info):
		err_info = self.get_err()
		self.logger.error(info+'\n'+err_info)


if __name__ == '__main__':
	kslog = KSLOG('1.log')
	kslog.info('测试')

