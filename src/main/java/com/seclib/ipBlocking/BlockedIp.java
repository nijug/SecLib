package com.seclib.ipBlocking;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
@Data
public class BlockedIp {

    @Id
    private String ip;

    protected BlockedIp() {}

    public BlockedIp(String ip) {
        this.ip = ip;
    }

}