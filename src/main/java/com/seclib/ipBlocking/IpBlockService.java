package com.seclib.ipBlocking;

public interface IpBlockService {
    void blockIp(String ip);
    void unblockIp(String ip);
}
