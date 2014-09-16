//package org.apache.hadoop.metrics2.lib;
//
//import static com.google.common.base.Preconditions.checkNotNull;
//import static org.apache.hadoop.metrics2.lib.Interns.*;
//
//import java.util.concurrent.atomic.AtomicInteger;
//
//import org.apache.hadoop.metrics2.MetricsInfo;
//import org.apache.hadoop.metrics2.MetricsRecordBuilder;
//
//public class MetricMutableRate extends MutableMetric {
//
//	private final MetricsInfo info;
//
//	private final AtomicInteger value;
//	private long prevRate;
//	private long ts;
//
//	public MetricMutableRate(String name) {
//		checkNotNull(name);
//		this.info = info(name, name);
//		this.value = new AtomicInteger(0);
//		this.prevRate = 0;
//		this.ts = System.currentTimeMillis();
//	}
//
//	public void incr(final int incr) {
//		value.addAndGet(incr);
//	}
//
//	public void intervalHeartBeat() {
//		int current = this.value.intValue();
//		long now = System.currentTimeMillis();
//		double diff = (now - ts) / 1000.0;
//		if (diff < 1.0) {
//			return;
//		}
//		this.prevRate = (long) (current / diff);
//		this.value.addAndGet(-current);
//		this.ts = now;
//	}
//
//	@Override
//	public void snapshot(MetricsRecordBuilder builder, boolean all) {
//		intervalHeartBeat();
//		builder.addGauge(this.info, this.prevRate);
//	}
//
//}
