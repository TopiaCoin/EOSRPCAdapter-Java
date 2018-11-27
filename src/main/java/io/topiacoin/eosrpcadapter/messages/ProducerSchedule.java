package io.topiacoin.eosrpcadapter.messages;

import java.util.Arrays;
import java.util.Map;

public class ProducerSchedule {
    public ProducersObject active;
    public ProducersObject pending;
    public ProducersObject proposed;
    public String error;

    @Override
    public String toString() {
        return "AccountInfo{" +
                "active='" + active + '\'' +
                ", pending=" + pending +
                ", proposed='" + proposed + '\'' +
                ", error='" + error + '\'' +
                '}';
    }

    public static class ProducersObject {
        public int version;
        public ProducerObject[] producers;

        @Override
        public String toString() {
            return "ProducersObject{" +
                    "version='" + version + '\'' +
                    ", producers=" + Arrays.toString(producers) +
                    '}';
        }
    }

    public static class ProducerObject {
        public String producer_name;
        public String block_signing_key;

        @Override
        public String toString() {
            return "Producer{" +
                    "producer_name=" + producer_name +
                    ", block_signing_key=" + block_signing_key +
                    '}';
        }
    }
}
