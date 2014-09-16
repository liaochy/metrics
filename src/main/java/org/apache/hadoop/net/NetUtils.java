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
package org.apache.hadoop.net;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.BindException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.NoRouteToHostException;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;

public class NetUtils {
	private static final Log LOG = LogFactory.getLog(NetUtils.class);

	private static Map<String, String> hostToResolved = new HashMap<String, String>();
	/** text to point users elsewhere: {@value} */
	private static final String FOR_MORE_DETAILS_SEE = " For more details see:  ";
	/** text included in wrapped exceptions if the host is null: {@value} */
	public static final String UNKNOWN_HOST = "(unknown)";
	/** Base URL of the Hadoop Wiki: {@value} */
	public static final String HADOOP_WIKI = "http://wiki.apache.org/hadoop/";

	/**
	 * Util method to build socket addr from either: <host>:<port>
	 * <fs>://<host>:<port>/<path>
	 */
	public static InetSocketAddress createSocketAddr(String target) {
		return createSocketAddr(target, -1);
	}

	/**
	 * Util method to build socket addr from either: <host> <host>:<port>
	 * <fs>://<host>:<port>/<path>
	 */
	public static InetSocketAddress createSocketAddr(String target,
			int defaultPort) {
		return createSocketAddr(target, defaultPort, null);
	}

	/**
	 * Create an InetSocketAddress from the given target string and default
	 * port. If the string cannot be parsed correctly, the
	 * <code>configName</code> parameter is used as part of the exception
	 * message, allowing the user to better diagnose the misconfiguration.
	 * 
	 * @param target
	 *            a string of either "host" or "host:port"
	 * @param defaultPort
	 *            the default port if <code>target</code> does not include a
	 *            port number
	 * @param configName
	 *            the name of the configuration from which <code>target</code>
	 *            was loaded. This is used in the exception message in the case
	 *            that parsing fails.
	 */
	public static InetSocketAddress createSocketAddr(String target,
			int defaultPort, String configName) {
		String helpText = "";
		if (configName != null) {
			helpText = " (configuration property '" + configName + "')";
		}
		if (target == null) {
			throw new IllegalArgumentException("Target address cannot be null."
					+ helpText);
		}
		boolean hasScheme = target.contains("://");
		URI uri = null;
		try {
			uri = hasScheme ? URI.create(target) : URI.create("dummyscheme://"
					+ target);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException(
					"Does not contain a valid host:port authority: " + target
							+ helpText);
		}

		String host = uri.getHost();
		int port = uri.getPort();
		if (port == -1) {
			port = defaultPort;
		}
		String path = uri.getPath();

		if ((host == null) || (port < 0)
				|| (!hasScheme && path != null && !path.isEmpty())) {
			throw new IllegalArgumentException(
					"Does not contain a valid host:port authority: " + target
							+ helpText);
		}
		return createSocketAddrForHost(host, port);
	}

	/**
	 * Create a socket address with the given host and port. The hostname might
	 * be replaced with another host that was set via
	 * {@link #addStaticResolution(String, String)}. The value of
	 * hadoop.security.token.service.use_ip will determine whether the standard
	 * java host resolver is used, or if the fully qualified resolver is used.
	 * 
	 * @param host
	 *            the hostname or IP use to instantiate the object
	 * @param port
	 *            the port number
	 * @return InetSocketAddress
	 */
	public static InetSocketAddress createSocketAddrForHost(String host,
			int port) {
		String staticHost = getStaticResolution(host);
		String resolveHost = (staticHost != null) ? staticHost : host;

		InetSocketAddress addr;
		try {
			InetAddress iaddr = SecurityUtil.getByName(resolveHost);
			// if there is a static entry for the host, make the returned
			// address look like the original given host
			if (staticHost != null) {
				iaddr = InetAddress.getByAddress(host, iaddr.getAddress());
			}
			addr = new InetSocketAddress(iaddr, port);
		} catch (UnknownHostException e) {
			addr = InetSocketAddress.createUnresolved(host, port);
		}
		return addr;
	}

	/**
	 * Resolve the uri's hostname and add the default port if not in the uri
	 * 
	 * @param uri
	 *            to resolve
	 * @param defaultPort
	 *            if none is given
	 * @return URI
	 */
	public static URI getCanonicalUri(URI uri, int defaultPort) {
		// skip if there is no authority, ie. "file" scheme or relative uri
		String host = uri.getHost();
		if (host == null) {
			return uri;
		}
		String fqHost = canonicalizeHost(host);
		int port = uri.getPort();
		// short out if already canonical with a port
		if (host.equals(fqHost) && port != -1) {
			return uri;
		}
		// reconstruct the uri with the canonical host and port
		try {
			uri = new URI(uri.getScheme(), uri.getUserInfo(), fqHost,
					(port == -1) ? defaultPort : port, uri.getPath(),
					uri.getQuery(), uri.getFragment());
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(e);
		}
		return uri;
	}

	// cache the canonicalized hostnames; the cache currently isn't expired,
	// but the canonicals will only change if the host's resolver configuration
	// changes
	private static final ConcurrentHashMap<String, String> canonicalizedHostCache = new ConcurrentHashMap<String, String>();

	private static String canonicalizeHost(String host) {
		// check if the host has already been canonicalized
		String fqHost = canonicalizedHostCache.get(host);
		if (fqHost == null) {
			try {
				fqHost = SecurityUtil.getByName(host).getHostName();
				// slight race condition, but won't hurt
				canonicalizedHostCache.put(host, fqHost);
			} catch (UnknownHostException e) {
				fqHost = host;
			}
		}
		return fqHost;
	}

	/**
	 * Adds a static resolution for host. This can be used for setting up
	 * hostnames with names that are fake to point to a well known host. For
	 * e.g. in some testcases we require to have daemons with different
	 * hostnames running on the same machine. In order to create connections to
	 * these daemons, one can set up mappings from those hostnames to
	 * "localhost". {@link NetUtils#getStaticResolution(String)} can be used to
	 * query for the actual hostname.
	 * 
	 * @param host
	 * @param resolvedName
	 */
	public static void addStaticResolution(String host, String resolvedName) {
		synchronized (hostToResolved) {
			hostToResolved.put(host, resolvedName);
		}
	}

	/**
	 * Retrieves the resolved name for the passed host. The resolved name must
	 * have been set earlier using
	 * {@link NetUtils#addStaticResolution(String, String)}
	 * 
	 * @param host
	 * @return the resolution
	 */
	public static String getStaticResolution(String host) {
		synchronized (hostToResolved) {
			return hostToResolved.get(host);
		}
	}

	/**
	 * This is used to get all the resolutions that were added using
	 * {@link NetUtils#addStaticResolution(String, String)}. The return value is
	 * a List each element of which contains an array of String of the form
	 * String[0]=hostname, String[1]=resolved-hostname
	 * 
	 * @return the list of resolutions
	 */
	public static List<String[]> getAllStaticResolutions() {
		synchronized (hostToResolved) {
			Set<Entry<String, String>> entries = hostToResolved.entrySet();
			if (entries.size() == 0) {
				return null;
			}
			List<String[]> l = new ArrayList<String[]>(entries.size());
			for (Entry<String, String> e : entries) {
				l.add(new String[] { e.getKey(), e.getValue() });
			}
			return l;
		}
	}

	/**
	 * Returns an InetSocketAddress that a client can use to connect to the
	 * given listening address.
	 * 
	 * @param addr
	 *            of a listener
	 * @return socket address that a client can use to connect to the server.
	 */
	public static InetSocketAddress getConnectAddress(InetSocketAddress addr) {
		if (!addr.isUnresolved() && addr.getAddress().isAnyLocalAddress()) {
			try {
				addr = new InetSocketAddress(InetAddress.getLocalHost(),
						addr.getPort());
			} catch (UnknownHostException uhe) {
				// shouldn't get here unless the host doesn't have a loopback
				// iface
				addr = createSocketAddrForHost("127.0.0.1", addr.getPort());
			}
		}
		return addr;
	}

	/**
	 * Given a string representation of a host, return its ip address in textual
	 * presentation.
	 * 
	 * @param name
	 *            a string representation of a host: either a textual
	 *            representation its IP address or its host name
	 * @return its IP address in the string format
	 */
	public static String normalizeHostName(String name) {
		try {
			return InetAddress.getByName(name).getHostAddress();
		} catch (UnknownHostException e) {
			return name;
		}
	}

	/**
	 * Given a collection of string representation of hosts, return a list of
	 * corresponding IP addresses in the textual representation.
	 * 
	 * @param names
	 *            a collection of string representations of hosts
	 * @return a list of corresponding IP addresses in the string format
	 * @see #normalizeHostName(String)
	 */
	public static List<String> normalizeHostNames(Collection<String> names) {
		List<String> hostNames = new ArrayList<String>(names.size());
		for (String name : names) {
			hostNames.add(normalizeHostName(name));
		}
		return hostNames;
	}

	/**
	 * Performs a sanity check on the list of hostnames/IPs to verify they at
	 * least appear to be valid.
	 * 
	 * @param names
	 *            - List of hostnames/IPs
	 * @throws UnknownHostException
	 */
	public static void verifyHostnames(String[] names)
			throws UnknownHostException {
		for (String name : names) {
			if (name == null) {
				throw new UnknownHostException("null hostname found");
			}
			// The first check supports URL formats (e.g. hdfs://, etc.).
			// java.net.URI requires a schema, so we add a dummy one if it
			// doesn't
			// have one already.
			URI uri = null;
			try {
				uri = new URI(name);
				if (uri.getHost() == null) {
					uri = new URI("http://" + name);
				}
			} catch (URISyntaxException e) {
				uri = null;
			}
			if (uri == null || uri.getHost() == null) {
				throw new UnknownHostException(name
						+ " is not a valid Inet address");
			}
		}
	}

	private static final Pattern ipPortPattern = // Pattern for matching
													// ip[:port]
	Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?");

	/**
	 * Attempt to obtain the host name of the given string which contains an IP
	 * address and an optional port.
	 * 
	 * @param ipPort
	 *            string of form ip[:port]
	 * @return Host name or null if the name can not be determined
	 */
	public static String getHostNameOfIP(String ipPort) {
		if (null == ipPort || !ipPortPattern.matcher(ipPort).matches()) {
			return null;
		}

		try {
			int colonIdx = ipPort.indexOf(':');
			String ip = (-1 == colonIdx) ? ipPort : ipPort.substring(0,
					ipPort.indexOf(':'));
			return InetAddress.getByName(ip).getHostName();
		} catch (UnknownHostException e) {
			return null;
		}
	}

	/**
	 * Return hostname without throwing exception.
	 * 
	 * @return hostname
	 */
	public static String getHostname() {
		try {
			return "" + InetAddress.getLocalHost();
		} catch (UnknownHostException uhe) {
			return "" + uhe;
		}
	}

	/**
	 * Compose a "host:port" string from the address.
	 */
	public static String getHostPortString(InetSocketAddress addr) {
		return addr.getHostName() + ":" + addr.getPort();
	}

	/**
	 * Checks if {@code host} is a local host name and return
	 * {@link InetAddress} corresponding to that address.
	 * 
	 * @param host
	 *            the specified host
	 * @return a valid local {@link InetAddress} or null
	 * @throws SocketException
	 *             if an I/O error occurs
	 */
	public static InetAddress getLocalInetAddress(String host)
			throws SocketException {
		if (host == null) {
			return null;
		}
		InetAddress addr = null;
		try {
			addr = SecurityUtil.getByName(host);
			if (NetworkInterface.getByInetAddress(addr) == null) {
				addr = null; // Not a local address
			}
		} catch (UnknownHostException ignore) {
		}
		return addr;
	}

	/**
	 * Given an InetAddress, checks to see if the address is a local address, by
	 * comparing the address with all the interfaces on the node.
	 * 
	 * @param addr
	 *            address to check if it is local node's address
	 * @return true if the address corresponds to the local node
	 */
	public static boolean isLocalAddress(InetAddress addr) {
		// Check if the address is any local or loop back
		boolean local = addr.isAnyLocalAddress() || addr.isLoopbackAddress();

		// Check if the address is defined on any interface
		if (!local) {
			try {
				local = NetworkInterface.getByInetAddress(addr) != null;
			} catch (SocketException e) {
				local = false;
			}
		}
		return local;
	}

	/**
	 * Take an IOException , the local host port and remote host port details
	 * and return an IOException with the input exception as the cause and also
	 * include the host details. The new exception provides the stack trace of
	 * the place where the exception is thrown and some extra diagnostics
	 * information. If the exception is BindException or ConnectException or
	 * UnknownHostException or SocketTimeoutException, return a new one of the
	 * same type; Otherwise return an IOException.
	 * 
	 * @param destHost
	 *            target host (nullable)
	 * @param destPort
	 *            target port
	 * @param localHost
	 *            local host (nullable)
	 * @param localPort
	 *            local port
	 * @param exception
	 *            the caught exception.
	 * @return an exception to throw
	 */
	public static IOException wrapException(final String destHost,
			final int destPort, final String localHost, final int localPort,
			final IOException exception) {
		if (exception instanceof BindException) {
			return new BindException("Problem binding to [" + localHost + ":"
					+ localPort + "] " + exception + ";" + see("BindException"));
		} else if (exception instanceof ConnectException) {
			// connection refused; include the host:port in the error
			return wrapWithMessage(exception, "Call From " + localHost + " to "
					+ destHost + ":" + destPort
					+ " failed on connection exception: " + exception + ";"
					+ see("ConnectionRefused"));
		} else if (exception instanceof UnknownHostException) {
			return wrapWithMessage(exception, "Invalid host name: "
					+ getHostDetailsAsString(destHost, destPort, localHost)
					+ exception + ";" + see("UnknownHost"));
		} else if (exception instanceof SocketTimeoutException) {
			return wrapWithMessage(exception, "Call From " + localHost + " to "
					+ destHost + ":" + destPort
					+ " failed on socket timeout exception: " + exception + ";"
					+ see("SocketTimeout"));
		} else if (exception instanceof NoRouteToHostException) {
			return wrapWithMessage(exception, "No Route to Host from  "
					+ localHost + " to " + destHost + ":" + destPort
					+ " failed on socket timeout exception: " + exception + ";"
					+ see("NoRouteToHost"));
		} else {
			return (IOException) new IOException("Failed on local exception: "
					+ exception + "; Host Details : "
					+ getHostDetailsAsString(destHost, destPort, localHost))
					.initCause(exception);

		}
	}

	private static String see(final String entry) {
		return FOR_MORE_DETAILS_SEE + HADOOP_WIKI + entry;
	}

	@SuppressWarnings("unchecked")
	private static <T extends IOException> T wrapWithMessage(T exception,
			String msg) {
		Class<? extends Throwable> clazz = exception.getClass();
		try {
			Constructor<? extends Throwable> ctor = clazz
					.getConstructor(String.class);
			Throwable t = ctor.newInstance(msg);
			return (T) (t.initCause(exception));
		} catch (Throwable e) {
			LOG.warn("Unable to wrap exception of type " + clazz
					+ ": it has no (String) constructor", e);
			return exception;
		}
	}

	/**
	 * Get the host details as a string
	 * 
	 * @param destHost
	 *            destinatioon host (nullable)
	 * @param destPort
	 *            destination port
	 * @param localHost
	 *            local host (nullable)
	 * @return a string describing the destination host:port and the local host
	 */
	private static String getHostDetailsAsString(final String destHost,
			final int destPort, final String localHost) {
		StringBuilder hostDetails = new StringBuilder(27);
		hostDetails.append("local host is: ").append(quoteHost(localHost))
				.append("; ");
		hostDetails.append("destination host is: ").append(quoteHost(destHost))
				.append(":").append(destPort).append("; ");
		return hostDetails.toString();
	}

	/**
	 * Quote a hostname if it is not null
	 * 
	 * @param hostname
	 *            the hostname; nullable
	 * @return a quoted hostname or {@link #UNKNOWN_HOST} if the hostname is
	 *         null
	 */
	private static String quoteHost(final String hostname) {
		return (hostname != null) ? ("\"" + hostname + "\"") : UNKNOWN_HOST;
	}

	/**
	 * @return true if the given string is a subnet specified using CIDR
	 *         notation, false otherwise
	 */
	public static boolean isValidSubnet(String subnet) {
		try {
			new SubnetUtils(subnet);
			return true;
		} catch (IllegalArgumentException iae) {
			return false;
		}
	}

	/**
	 * Add all addresses associated with the given nif in the given subnet to
	 * the given list.
	 */
	private static void addMatchingAddrs(NetworkInterface nif,
			SubnetInfo subnetInfo, List<InetAddress> addrs) {
		Enumeration<InetAddress> ifAddrs = nif.getInetAddresses();
		while (ifAddrs.hasMoreElements()) {
			InetAddress ifAddr = ifAddrs.nextElement();
			if (subnetInfo.isInRange(ifAddr.getHostAddress())) {
				addrs.add(ifAddr);
			}
		}
	}

	/**
	 * Return an InetAddress for each interface that matches the given subnet
	 * specified using CIDR notation.
	 * 
	 * @param subnet
	 *            subnet specified using CIDR notation
	 * @param returnSubinterfaces
	 *            whether to return IPs associated with subinterfaces
	 * @throws IllegalArgumentException
	 *             if subnet is invalid
	 */
	public static List<InetAddress> getIPs(String subnet,
			boolean returnSubinterfaces) {
		List<InetAddress> addrs = new ArrayList<InetAddress>();
		SubnetInfo subnetInfo = new SubnetUtils(subnet).getInfo();
		Enumeration<NetworkInterface> nifs;

		try {
			nifs = NetworkInterface.getNetworkInterfaces();
		} catch (SocketException e) {
			LOG.error("Unable to get host interfaces", e);
			return addrs;
		}

		while (nifs.hasMoreElements()) {
			NetworkInterface nif = nifs.nextElement();
			// NB: adding addresses even if the nif is not up
			addMatchingAddrs(nif, subnetInfo, addrs);

			if (!returnSubinterfaces) {
				continue;
			}
			Enumeration<NetworkInterface> subNifs = nif.getSubInterfaces();
			while (subNifs.hasMoreElements()) {
				addMatchingAddrs(subNifs.nextElement(), subnetInfo, addrs);
			}
		}
		return addrs;
	}

	/**
	 * Return a free port number. There is no guarantee it will remain free, so
	 * it should be used immediately.
	 * 
	 * @returns A free port for binding a local socket
	 */
	public static int getFreeSocketPort() {
		int port = 0;
		try {
			ServerSocket s = new ServerSocket(0);
			port = s.getLocalPort();
			s.close();
			return port;
		} catch (IOException e) {
			// Could not get a free port. Return default port 0.
		}
		return port;
	}
}
