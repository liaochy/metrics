package com.sohu;

public class RestMetrics {

	public static void addStatusCount(String url, Integer status,
			int processTime) {
		RestTotalMetrics.create().addStatusCount(status, processTime);
		RestUrlMetrics.create().addProcessTime(url, processTime); 
	}
}
