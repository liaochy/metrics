package com.sohu;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.metrics2.annotation.Metric;
import org.apache.hadoop.metrics2.annotation.Metrics;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;
import org.apache.hadoop.metrics2.lib.MutableRates;

@Metrics(about = "Jersey REST  for one url", context = "url")
public class RestUrlMetrics {
	private static final Map<String, RestUrlMetrics> urls = new ConcurrentHashMap<String, RestUrlMetrics>();
	private static final ConcurrentHashMap<String, String> urlLock = new ConcurrentHashMap<String, String>();

	static final Log LOG = LogFactory.getLog(RestUrlMetrics.class);
	private final String url;

	RestUrlMetrics(String url) {
		this.url = url;
	}

	public static RestUrlMetrics create(String url) {
		RestUrlMetrics source = null;
		urlLock.putIfAbsent(url, url);
		synchronized (urlLock.get(url)) {
			source = urls.get(url);
			if (source == null) {
				RestUrlMetrics m = new RestUrlMetrics(url);
				RestUrlMetrics metrics = DefaultMetricsSystem.instance()
						.register(m.url, null, m);
				urls.put(url, metrics);
			}
		}
		return urls.get(url);
	}

	@Metric(sampleName = "count")
	MutableRates rates;

	public void init(Class<?> protocol) {
		rates.init(protocol);
	}

	public void addStatusCount(Integer status, int processTime) {
		rates.add(url+"_"+String.valueOf(status), processTime);
		rates.add("all", processTime);
	}

}
