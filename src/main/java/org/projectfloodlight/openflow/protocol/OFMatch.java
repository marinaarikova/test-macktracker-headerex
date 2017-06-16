package org.projectfloodlight.openflow.protocol;

import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpDscp;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.Masked;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFValueType;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.VlanPcp;

import com.google.common.hash.PrimitiveSink;

import io.netty.buffer.ByteBuf;

public class OFMatch implements OFMatchV1 {

	@Override
	public void putTo(PrimitiveSink arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public <F extends OFValueType<F>> F get(MatchField<F> arg0) throws UnsupportedOperationException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public <F extends OFValueType<F>> Masked<F> getMasked(MatchField<F> arg0) throws UnsupportedOperationException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Iterable<MatchField<?>> getMatchFields() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isExact(MatchField<?> arg0) throws UnsupportedOperationException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isFullyWildcarded(MatchField<?> arg0) throws UnsupportedOperationException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isPartiallyMasked(MatchField<?> arg0) throws UnsupportedOperationException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean supports(MatchField<?> arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean supportsMasked(MatchField<?> arg0) throws UnsupportedOperationException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Builder createBuilder() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public MacAddress getEthDst() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public MacAddress getEthSrc() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public EthType getEthType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OFPort getInPort() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IpDscp getIpDscp() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IpProtocol getIpProto() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IPv4Address getIpv4Dst() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IPv4Address getIpv4Src() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TransportPort getTcpDst() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TransportPort getTcpSrc() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OFVersion getVersion() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VlanPcp getVlanPcp() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OFVlanVidMatch getVlanVid() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getWildcards() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void writeTo(ByteBuf arg0) {
		// TODO Auto-generated method stub

	}

	public byte[] getDataLayerDestination() {
		// TODO Auto-generated method stub
		return null;
	}

	public void loadFromPacket(byte[] data, OFPort inPort) {
		// TODO Auto-generated method stub
		
	}

	public int getNetworkDestination() {
		// TODO Auto-generated method stub
		return 0;
	}

}
