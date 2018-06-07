package io.topiacoin.eosrpcadapter.messages;

public class GetInfo {
    public static class Request {

    }

    public static class Response {
        public String server_version;
        public long head_block_num;
        public long last_irreversible_block_num;
        public String head_block_id;
        public String head_block_time;
        public String head_block_producer;

        @Override
        public String toString() {
            return "Response{" +
                    "server_version='" + server_version + '\'' +
                    ", head_block_num=" + head_block_num +
                    ", last_irreversible_block_num=" + last_irreversible_block_num +
                    ", head_block_id='" + head_block_id + '\'' +
                    ", head_block_time='" + head_block_time + '\'' +
                    ", head_block_producer='" + head_block_producer + '\'' +
                    '}';
        }
    }
}
