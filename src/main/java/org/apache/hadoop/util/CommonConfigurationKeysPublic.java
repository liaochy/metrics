/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.util;

/**
 * This class contains constants for configuration keys used in the common code.
 * 
 * It includes all publicly documented configuration keys. In general this class
 * should not be used directly (use CommonConfigurationKeys instead)
 * 
 */

public class CommonConfigurationKeysPublic {

	public static final String HADOOP_RPC_SOCKET_FACTORY_CLASS_DEFAULT_KEY = "hadoop.rpc.socket.factory.class.default";
	public static final String HADOOP_RPC_SOCKET_FACTORY_CLASS_DEFAULT_DEFAULT = "org.apache.hadoop.net.StandardSocketFactory";

	  public static final String HADOOP_SECURITY_TOKEN_SERVICE_USE_IP =
		      "hadoop.security.token.service.use_ip";
		  public static final boolean HADOOP_SECURITY_TOKEN_SERVICE_USE_IP_DEFAULT =
		      true;
}
