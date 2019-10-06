package net.floodlightcontroller.natcs5229;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.*;
import java.io.IOException;
import java.util.*;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.concurrent.ConcurrentSkipListSet;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.projectfloodlight.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;


/**
 * Created by pravein on 28/9/17.
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    HashMap<String, String> RouterInterfaceMacMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();
	protected Map<IPAddress, Set<ARPRequest>> arpRequests;
	protected IDeviceService deviceManager;
	protected ITopologyService topologyManager;


    @Override
    public String getName() {
        return NAT.class.getName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }





    // Main Place to Handle PacketIN to perform NAT
    private Command handlePacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	IPacket pkt = eth.getPayload();
	if (eth.isBroadcast() || eth.isMulticast()){
	
		if (pkt instanceof ARP){
			ARP arpRequest = (ARP) eth.getPayload();
			IPv4Address targetProtocolAddress = arpRequest.getTargetProtocolAddress();
			String srcIp = arpRequest.getSenderProtocolAddress().toString();

			System.out.println("Getting ARP for: "+targetProtocolAddress.toString());
			
			System.out.println("Requestor : "+srcIp + " from : "+ pi.getMatch().get(MatchField.IN_PORT).getPortNumber());

			if (arpRequest.getOpCode() == ARP.OP_REQUEST) {
				return this.handleARPRequest(arpRequest, sw, pi, cntx);
			}
			
			// Handle ARP reply.
			if (arpRequest.getOpCode() == ARP.OP_REPLY) {
				return this.handleARPReply(arpRequest, sw, pi, cntx);
			}

		}
	} else{
		if (pkt instanceof IPv4){
			IPv4 ip_pkt = (IPv4) pkt;
			
			byte[] ipOptions = ip_pkt.getOptions();
			IPv4Address dstIp = ip_pkt.getDestinationAddress();

			if (ip_pkt.getProtocol() == IpProtocol.TCP) {
				/* We got a TCP packet; get the payload from IPv4 */
				TCP tcp = (TCP) ip_pkt.getPayload();
				
				/* Various getters and setters are exposed in TCP */
				TransportPort srcPort = tcp.getSourcePort();
				TransportPort dstPort = tcp.getDestinationPort();
				short flags = tcp.getFlags();
				 
				/* Your logic here! */
			} else if (ip_pkt.getProtocol() == IpProtocol.UDP) {
				/* We got a UDP packet; get the payload from IPv4 */
				UDP udp = (UDP) ip_pkt.getPayload();
				
				/* Various getters and setters are exposed in UDP */
				TransportPort srcPort = udp.getSourcePort();
				TransportPort dstPort = udp.getDestinationPort();
				 
				/* Your logic here! */
	            }

		}
	}



	return Command.CONTINUE;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch(msg.getType()) {
            case PACKET_IN:
                return handlePacketIn(sw, (OFPacketIn)msg, cntx);
            default:
                break;
        }
        logger.warn("Received unexpected message {}", msg);
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(NAT.class);

        // Use the below HashMaps as per your need

        // Router Interface IP to Mac address Mappings
        RouterInterfaceMacMap.put("10.0.0.1","00:23:10:00:00:01");
        RouterInterfaceMacMap.put("192.168.0.1","00:23:10:00:00:02");
        RouterInterfaceMacMap.put("192.168.0.2","00:23:10:00:00:03");

        // IP to Router Interface mappings
        IPPortMap.put("192.168.0.10", OFPort.of(1));
        IPPortMap.put("192.168.0.20", OFPort.of(2));
        IPPortMap.put("10.0.0.11", OFPort.of(3));

        //Client/Server ip to Mac mappings
        IPMacMap.put("192.168.0.10", "00:00:00:00:00:01");
        IPMacMap.put("192.168.0.20", "00:00:00:00:00:02");
        IPMacMap.put("10.0.0.11", "00:00:00:00:00:03");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }


	//Extra Code here:


	
	protected class ARPRequest {
		private MacAddress sourceMACAddress;
		private IPv4Address sourceIPAddress;
		private MacAddress targetMACAddress;
		private IPv4Address targetIPAddress;
		private long switchId;
		private short inPort;
		private long startTime;
		
		/** 
		 * Setter for the IP address of the source host that initialized the ARP request.
		 * 
		 * @param sourceMACAddress The IP address of the source host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSourceMACAddress(MacAddress sourceMACAddress) {
			this.sourceMACAddress = sourceMACAddress;
			return this;
		}
		
		/**
		 * Setter for the IP address of the source host that initialized the ARP request.
		 * 
		 * @param sourceIPAddress The IP address of the source host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSourceIPAddress(IPv4Address sourceIPAddress) {
			this.sourceIPAddress = sourceIPAddress;
			return this;
		}
		
		/**
		 * Setter for the MAC address of the target (destination) host.
		 * 
		 * @param targetMACAddress The MAC address of the target (destination) host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setTargetMACAddress(MacAddress targetMACAddress) {
			this.targetMACAddress = targetMACAddress;
			return this;
		}
		
		/**
		 * Setter for the IP address of the target (destination) host.
		 * 
		 * @param targetIPAddress The IP address of the target (destination) host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setTargetIPAddress(IPv4Address targetIPAddress) {
			this.targetIPAddress = targetIPAddress;
			return this;
		}
		
		/**
		 * Setter for the SwitchId where the ARP request is received.
		 * 
		 * @param switchId Where the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSwitchId(long switchId) {
			this.switchId = switchId;
			return this;
		}
		
		/**
		 * Setter for the PortId where the ARP request is received.
		 * 
		 * @param portId Where the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setInPort(short portId) {
			this.inPort = portId;
			return this;
		}
		
		/**
		 * Setter for the start time when the ARP request is received.
		 * 
		 * @param startTime The time when the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setStartTime(long startTime) {
			this.startTime = startTime;
			return this;
		}
		
		/**
		 * Getter for the source MAC address, i.e from the node that initialized the ARP request.
		 * 
		 * @return <b>long</b> The MAC address of the source of the ARP request. 
		 */
		public MacAddress getSourceMACAddress() {
			return this.sourceMACAddress;
		}
		
		/**
		 * Getter for the source IP address, i.e. from the node that initialized the ARP request.
		 * 
		 * @return <b>long</b> The IP address of the source of the ARP request. 
		 */
		public IPv4Address getSourceIPAddress() {
			return this.sourceIPAddress;
		}
		
		/**
		 * Getter for the target (destination) MAC address.
		 * 
		 * @return <b>long</b> The MAC address of the target (destination) of the ARP request. 
		 */
		public MacAddress getTargetMACAddress() {
			return this.targetMACAddress;
		}
		
		/**
		 * Getter for the target (destination) IP address.
		 * 
		 * @return <b>long</b> The IP address of the target (destination) of the ARP request. 
		 */
		public IPv4Address getTargetIPAddress() {
			return this.targetIPAddress;
		}
		
		/**
		 * Getter for the switch ID of the ARP incoming switch.
		 * 
		 * @return <b>long</b> The switch ID of the switch where the ARP request is received.
		 */
		public long getSwitchId() {
			return this.switchId;
		}
		
		/**
		 * Getter for the port ID if the ARP incoming port.
		 * 
		 * @return <b>short</b> The port ID of the port where the ARP request is received.
		 */
		public short getInPort() {
			return this.inPort;
		}
		
		/**
		 * Getter for the start time of the ARP request.
		 * 
		 * @return <b>long</b> The start time when the ARP request is received.
		 */
		public long getStartTime() {
			return this.startTime;
		}
	}



	
	protected Command handleARPRequest(ARP arp, IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		/* The known IP address of the ARP source. */
		IPv4Address sourceIPAddress = arp.getSenderProtocolAddress();
		/* The known MAC address of the ARP source. */
		MacAddress sourceMACAddress = arp.getSenderHardwareAddress();
		/* The IP address of the (yet unknown) ARP target. */
		IPv4Address targetIPAddress = arp.getTargetProtocolAddress();
		/* The MAC address of the (yet unknown) ARP target. */
		MacAddress targetMACAddress;
		
		/*
		// Check if there is an ongoing ARP process for this packet.
		if (arpRequests.get(targetIPAddress)!=null) {
			// Update start time of current ARPRequest objects
			long startTime = System.currentTimeMillis();
			Set<ARPRequest> arpRequestSet = arpRequests.get(targetIPAddress);
			
			for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
				iter.next().setStartTime(startTime);
			}
			return Command.STOP;
		}*/
		
		
		@SuppressWarnings("unchecked")
		Iterator<Device> diter = (Iterator<Device>) deviceManager.queryDevices(MacAddress.NONE, null, arp.getTargetProtocolAddress(), IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);

		// There should be only one MAC address to the given IP address. In any case, 
		// we return only the first MAC address found.
		if (diter.hasNext()) {
			// If we know the destination device, get the corresponding MAC address and send an ARP reply.
			Device device = diter.next();
			targetMACAddress = device.getMACAddress();
			//long age = System.currentTimeMillis() - device.getLastSeen().getTime();
			
			//if (targetMACAddress > 0 && age < ARP_TIMEOUT) {
			if (targetMACAddress.getLong() > 0) {
				ARPRequest arpRequest = new ARPRequest()
					.setSourceMACAddress(sourceMACAddress)
					.setSourceIPAddress(sourceIPAddress)
					.setTargetMACAddress(targetMACAddress)
					.setTargetIPAddress(targetIPAddress)
					.setSwitchId(sw.getId().getLong())
					.setInPort(pi.getInPort().getShortPortNumber());
				// Send ARP reply.
				this.sendARPReply(arpRequest, sw, pi);
			} else {
				ARPRequest arpRequest = new ARPRequest()
					.setSourceMACAddress(sourceMACAddress)
					.setSourceIPAddress(sourceIPAddress)
					.setTargetIPAddress(targetIPAddress)
					.setSwitchId(sw.getId().getLong())
					.setInPort(pi.getInPort().getShortPortNumber())
					.setStartTime(System.currentTimeMillis());
				this.putArpRequest(targetIPAddress, arpRequest);
				// Send ARP request.
				this.sendARPRequest(arpRequest, sw, pi);
			}
			
		} else {
			ARPRequest arpRequest = new ARPRequest()
				.setSourceMACAddress(sourceMACAddress)
				.setSourceIPAddress(sourceIPAddress)
				.setTargetIPAddress(targetIPAddress)
				.setSwitchId(sw.getId().getLong())
				.setInPort(pi.getInPort().getShortPortNumber())
				.setStartTime(System.currentTimeMillis());
			this.putArpRequest(targetIPAddress, arpRequest);
			// Send ARP request
			this.sendARPRequest(arpRequest, sw, pi);
		}
		
		// Make a routing decision and forward the ARP message
		IRoutingDecision decision = new RoutingDecision(sw.getId(), pi.getInPort(), IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), IRoutingDecision.RoutingAction.NONE);
		
		return Command.CONTINUE;
	}

	protected void sendARPReply(ARPRequest arpRequest, IOFSwitch sw, OFPacketIn pi) {
		// Create an ARP reply frame (from target (source) to source (destination)).
		IPacket arpReply = new Ethernet()
				.setSourceMACAddress(arpRequest.getTargetMACAddress())
				.setDestinationMACAddress(arpRequest.getSourceMACAddress())
				.setEtherType(EthType.ARP)
				.setPayload(new ARP()
						.setHardwareType(ARP.HW_TYPE_ETHERNET)
						.setProtocolType(ARP.PROTO_TYPE_IP)
						.setOpCode(ARP.OP_REPLY)
						.setHardwareAddressLength((byte)6)
						.setProtocolAddressLength((byte)4)
						.setSenderHardwareAddress(arpRequest.getTargetMACAddress())
						.setSenderProtocolAddress(arpRequest.getTargetIPAddress())
						.setTargetHardwareAddress(arpRequest.getSourceMACAddress())
						.setTargetProtocolAddress(arpRequest.getSourceIPAddress())
						.setPayload(new Data(new byte[] {0x01})));
		// Send ARP reply.
		sendPOMessage(arpReply, sw, arpRequest.getInPort(), pi);
		if (logger.isDebugEnabled()) {
			logger.info("Send ARP reply to " + HexString.toHexString(arpRequest.getSwitchId()) + " at port " + arpRequest.getInPort());
		}
	}

	protected void sendARPRequest(ARPRequest arpRequest, IOFSwitch sw, OFPacketIn pi) {
		// Create an ARP request frame
		IPacket arpReply = new Ethernet()
				.setSourceMACAddress(arpRequest.getSourceMACAddress())
				.setDestinationMACAddress(arpRequest.getTargetMACAddress())
				.setEtherType(EthType.ARP)
				.setPayload(new ARP()
						.setHardwareType(ARP.HW_TYPE_ETHERNET)
						.setProtocolType(ARP.PROTO_TYPE_IP)
						.setOpCode(ARP.OP_REQUEST)
						.setHardwareAddressLength((byte)6)
						.setProtocolAddressLength((byte)4)
						.setSenderHardwareAddress(arpRequest.getSourceMACAddress())
						.setSenderProtocolAddress(arpRequest.getSourceIPAddress())
						.setTargetHardwareAddress(arpRequest.getTargetMACAddress())
						.setTargetProtocolAddress(arpRequest.getTargetIPAddress())
						.setPayload(new Data(new byte[] {0x01})));

		// Send ARP request to all external ports (i.e. attachment point ports).
		for (OFPortDesc port : sw.getPorts()) {
			short portId = port.getPortNo().getShortPortNumber();
			if (sw.getId().getLong() == arpRequest.getSwitchId() && portId == arpRequest.getInPort()) {
				continue;
			}
			if (topologyManager.isAttachmentPointPort(sw.getId(), port.getPortNo()))
				this.sendPOMessage(arpReply, sw, portId, pi);
			if (logger.isDebugEnabled()) {
				logger.debug("Send ARP request to " + HexString.toHexString(sw.getId().getBytes()) + " at port " + portId);
			}
		}

	}

	protected void sendPOMessage(IPacket packet, IOFSwitch sw, short port, OFPacketIn pi) {
		// Serialize and wrap in a packet out
		byte[] data = packet.serialize();
		//OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(pi.getBufferId());
		pob.setInPort(pi.getInPort());



		// Set actions
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(sw.getOFFactory().actions().buildOutput().setPort(OFPort.TABLE).setMaxLen(Integer.MAX_VALUE).build());
		//actions.add(new OFActionOutput(port, (short) 0));
		pob.setActions(actions);
		//po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

		// Set data
		//pob.setLengthU(OFPacketOut.MINIMUM_LENGTH + po.getActionsLength() + data.length);
		//pob.setPacketData(data);
		if (pob.getBufferId() == OFBufferId.NO_BUFFER) {
			if (packet == null) {
				logger.error("BufferId is not set and packet data is null. " +
								"Cannot send packetOut. " +
								"srcSwitch={} inPort={} outPort={}",
						new Object[] {sw, pi.getInPort(), OFPort.TABLE});
				return;
			}
			pob.setData(data);
		}

		// Send message
		try {
			sw.write(pob.build());
			//sw.flush();
		} catch (Exception e) {
			logger.error("Failure sending ARP out port {} on switch {}, {}", new Object[] { port, sw.getId() }, e);
		}
	}


	private void putArpRequest(IPAddress targetIPAddress, ARPRequest arpRequest) {
		if (arpRequests.containsKey(targetIPAddress)) {
			arpRequests.get(targetIPAddress).add(arpRequest);
		} else {
			arpRequests.put(targetIPAddress, new HashSet<ARPRequest>());
			arpRequests.get(targetIPAddress).add(arpRequest);
		}
	}


	protected Command handleARPReply(ARP arp, IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		/* The IP address of the ARP target. */
		IPv4Address targetIPAddress = arp.getSenderProtocolAddress();
		/* The set of APRRequest objects related to the target IP address.*/
		Set<ARPRequest> arpRequestSet = arpRequests.remove(targetIPAddress);
		/* The ARPRequenst object related to the ARP reply message. */
		ARPRequest arpRequest;

		if (logger.isDebugEnabled()) {
			logger.debug("Received ARP reply message from " + arp.getSenderHardwareAddress() + " at " + HexString.toHexString(sw.getId().getBytes()) + " - " + pi.getInPort());
		}

		// If the ARP request has already timed out, consume the message.
		// The sending host should send a new request, actually.
		if (arpRequestSet == null)
			return Command.STOP;

		for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
			arpRequest = iter.next();
			iter.remove();
			arpRequest.setTargetMACAddress(arp.getSenderHardwareAddress());
			sendARPReply(arpRequest, sw, pi);
		}

		// Make a routing decision and forward the ARP message
		IRoutingDecision decision = new RoutingDecision(sw.getId(), pi.getInPort(), IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), IRoutingDecision.RoutingAction.NONE);
		decision.addToContext(cntx);

		return Command.CONTINUE;
	}















}
