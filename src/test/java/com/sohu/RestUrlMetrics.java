package com.sohu;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.metrics2.annotation.Metric;
import org.apache.hadoop.metrics2.annotation.Metrics;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;
import org.apache.hadoop.metrics2.lib.MutableRates;

@Metrics(about = "Jersey REST  for one url", context = "jersey", name = "url")
public class RestUrlMetrics {

	static final Log LOG = LogFactory.getLog(RestUrlMetrics.class);
	private static RestUrlMetrics urlMetrics;

	private RestUrlMetrics() {
	}

	public static RestUrlMetrics create() {
		synchronized (RestTotalMetrics.class) {
			if (urlMetrics == null) {
				RestUrlMetrics metrics = new RestUrlMetrics();
				urlMetrics = DefaultMetricsSystem.instance().register(
						"url", null, metrics);
			}
		}
		return urlMetrics;
	}

	@Metric("process time")
	MutableRates rates;

	public void addProcessTime(String url, int processTime) {
		rates.add(url, processTime);
	}

}
