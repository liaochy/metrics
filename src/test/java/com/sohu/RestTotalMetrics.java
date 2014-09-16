package com.sohu;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.metrics2.annotation.Metric;
import org.apache.hadoop.metrics2.annotation.Metrics;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;
import org.apache.hadoop.metrics2.lib.MutableRates;

@Metrics(about = "Jersey REST connection metrics", context = "total")
public class RestTotalMetrics {

	static final Log LOG = LogFactory.getLog(RestTotalMetrics.class);
	private static RestTotalMetrics restTotalMetrics = null;

	private RestTotalMetrics() {
	}

	public static RestTotalMetrics create() {
		synchronized (RestTotalMetrics.class) {
			if (restTotalMetrics == null) {
				RestTotalMetrics metrics = new RestTotalMetrics();
				restTotalMetrics = DefaultMetricsSystem.instance().register(
						"total", null, metrics);
			}
		}
		return restTotalMetrics;
	}

	@Metric(sampleName = "count")
	MutableRates rates;

	public void init(Class<?> protocol) {
		rates.init(protocol);
	}

	public void addStatusCount(Integer status, int processTime) {
		rates.add(String.valueOf(status), processTime);
		rates.add("all", processTime);
	}

}
