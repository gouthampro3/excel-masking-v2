#!/home/lone/Documents/job_se/excel-masking-v2/reqlib/bin/python
import sys
import string
from io import StringIO
from struct import pack
import base64
import json
import argparse
import random

import boto3
from botocore.exceptions import ClientError
import pandas as pd
from Crypto.Hash import MD5

class Masker():
	def __init__(self,source_file_name):
		self.s3 = boto3.client('s3')
		self.file_name=source_file_name
		self.json_log={}

	def get_from_s3(self,bucket_name,object_name,local_file_name):
		self.s3.download_file(bucket_name,object_name,local_file_name)
	
	def start_process(self,data_file_name,conf_file_name):
		self.df=pd.read_csv(data_file_name)
		with open(conf_file_name) as conf:
			self.conf =	json.load(conf)
		for i in self.conf.keys():
			if(self.conf[i]['mask_type']=='irreversible'):
				self.maskcol(i,self.conf[i]['data_type'],self.conf[i]['mask_type'])	
			elif(self.conf[i]['mask_type']=='reversible'):
				self.maskcol(i,self.conf[i]['data_type'],self.conf[i]['mask_type'])	
			elif(self.conf[i]['mask_type']=='none'):
				continue
		self.save_to_object()
		self.calculate_convertedfile_md5()
		self.save_local()
		return 0;

	def maskcol(self,column,data_type,mask_type):
		self.json_log[column]={}
		self.json_log[column]['data_type']=data_type
		self.json_log[column]['mask_type']=mask_type
		self.json_log[column]['values']={}
		temp_dict={}
		col_len = len(str(len(self.df[column])))
		if(data_type=='int'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]= '0'*(col_len-len(str(i)))+str(i)
					temp_store=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
					"""for future use?
					int_len=len(str(self.df.loc[i,column]))
					if(int_len==1):
						while(random_num in temp_dict.keys()):
							random_num = random.randint(0,9)
					else:
						while(random_num in temp_dict.keys()):
							random_num = random.randint(pow(10,int_len-1),int('9'*int_len))
					"""
		elif(data_type=='float'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]=str(i+round(random.uniform(0,1),len(str(self.df.loc[i,column]).split('.')[-1])))
					temp_store=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]

		elif(data_type=='string'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]= column+'0'*(col_len-len(str(i)))+str(i)
					temp_store=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]

		elif(data_type=='email'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]= column+str(i)+'@domain'+str(i)+'.xyz'
					temp_store=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
			"""probably of no use
			elif(data_type=='gender'):
				for i in range(0,col_len):
					temp_dict[i]= random.sample(['Male','Female'],1)[0]
					self.df.loc[i,column]=temp_dict[i]
			"""

		elif(data_type=='phone_number'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					num_int=0
					for j in self.df.loc[i,column]:
						if (j.isdigit()):
							num_int+=1
					randnum='0'*(num_int-len(str(i)))+str(i)
					randnum_format=''
					count=0
					for j in self.df.loc[i,column]:
						if (j.isdigit()):
							randnum_format+=randnum[count]
							count+=1
						else:
							randnum_format+=j
					temp_dict[self.df.loc[i,column]]= randnum_format
					temp_store=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
		return 0

	def save_to_object(self):
		self.converted_fileobj=StringIO()
		self.df.to_csv(path_or_buf=self.converted_fileobj,index=False)
	
	def calculate_convertedfile_md5(self):
		self.md5=MD5.new(self.converted_fileobj.getvalue().encode('utf8')).hexdigest()
		self.json_log['md5']=self.md5

	def save_local(self):
		self.calculate_convertedfile_md5()
		self.masked_file_name=(self.file_name).split('.')[0]+'_md5_'+self.md5+'.'+(self.file_name).split('.')[1]
		self.log_filename=self.md5+'.json'
		self.json_log['masked_file_name']=self.masked_file_name
		with open(self.masked_file_name, 'w+') as masked_file:
			masked_file.write(self.converted_fileobj.getvalue())
		with open(self.log_filename,'w+') as logfile:
			json.dump(self.json_log,logfile)
		self.json_log['log_filename']=self.log_filename
		return 0

	def upload_to_s3(self,bucket):
		s3_client = boto3.client('s3')
		try:
			response = s3_client.upload_file(self.masked_file_name, bucket, self.masked_file_name)
		except ClientError as e:
			return (False,e)
		try:
			response = s3_client.upload_file(self.log_filename, 'masked-logstore', self.log_filename)
		except ClientError as e:
			return (False,e)
		print("The files masked file : %s is in bucket masked-filestore \nLogfile: %s is in bucket masked-logstore\n"%(self.masked_file_name,self.log_filename))
				

if __name__ == '__main__':
	mask_plz = Masker('MOCK_DATA.csv')
	mask_plz.get_from_s3('unmasked-filestore','MOCK_DATA.csv','MOCK_DATA.csv')
	mask_plz.get_from_s3('unmasked-filestore','MOCK_DATA.json','MOCK_DATA.json')
	mask_plz.start_process('MOCK_DATA.csv','MOCK_DATA.json')
	mask_plz.upload_to_s3('masked-filestore')