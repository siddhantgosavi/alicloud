# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from aliyunsdkcore.request import RpcRequest
from aliyunsdksas.endpoint import endpoint_data

class DescribePropertyScaDetailRequest(RpcRequest):

	def __init__(self):
		RpcRequest.__init__(self, 'Sas', '2018-12-03', 'DescribePropertyScaDetail','sas')
		self.set_method('POST')
		if hasattr(self, "endpoint_map"):
			setattr(self, "endpoint_map", endpoint_data.getEndpointMap())
		if hasattr(self, "endpoint_regional"):
			setattr(self, "endpoint_regional", endpoint_data.getEndpointRegional())


	def get_SearchItemSub(self):
		return self.get_query_params().get('SearchItemSub')

	def set_SearchItemSub(self,SearchItemSub):
		self.add_query_param('SearchItemSub',SearchItemSub)

	def get_Remark(self):
		return self.get_query_params().get('Remark')

	def set_Remark(self,Remark):
		self.add_query_param('Remark',Remark)

	def get_SearchItem(self):
		return self.get_query_params().get('SearchItem')

	def set_SearchItem(self,SearchItem):
		self.add_query_param('SearchItem',SearchItem)

	def get_Uuid(self):
		return self.get_query_params().get('Uuid')

	def set_Uuid(self,Uuid):
		self.add_query_param('Uuid',Uuid)

	def get_PageSize(self):
		return self.get_query_params().get('PageSize')

	def set_PageSize(self,PageSize):
		self.add_query_param('PageSize',PageSize)

	def get_Lang(self):
		return self.get_query_params().get('Lang')

	def set_Lang(self,Lang):
		self.add_query_param('Lang',Lang)

	def get_SearchInfoSub(self):
		return self.get_query_params().get('SearchInfoSub')

	def set_SearchInfoSub(self,SearchInfoSub):
		self.add_query_param('SearchInfoSub',SearchInfoSub)

	def get_SearchInfo(self):
		return self.get_query_params().get('SearchInfo')

	def set_SearchInfo(self,SearchInfo):
		self.add_query_param('SearchInfo',SearchInfo)

	def get_CurrentPage(self):
		return self.get_query_params().get('CurrentPage')

	def set_CurrentPage(self,CurrentPage):
		self.add_query_param('CurrentPage',CurrentPage)

	def get_BizType(self):
		return self.get_query_params().get('BizType')

	def set_BizType(self,BizType):
		self.add_query_param('BizType',BizType)

	def get_Name(self):
		return self.get_query_params().get('Name')

	def set_Name(self,Name):
		self.add_query_param('Name',Name)

	def get_ScaName(self):
		return self.get_query_params().get('ScaName')

	def set_ScaName(self,ScaName):
		self.add_query_param('ScaName',ScaName)