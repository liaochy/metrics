package com.sohu;

import java.io.IOException;
import java.util.Random;

import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;

public class Modules {
	public static void main(String[] args) throws InterruptedException,
			IOException, ClassNotFoundException, InstantiationException,
			IllegalAccessException {
		DefaultMetricsSystem.initialize("jersey");
		Random random = new Random(10);
		while (true) {
			for (int i = 0; i < 4; i++) {
				RestMetrics.addStatusCount("/url/" + i, 300 + random.nextInt(4),
						random.nextInt(1000));
			}
			Thread.currentThread().sleep(100);

		}
	}
}
