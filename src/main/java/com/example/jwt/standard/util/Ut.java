package com.example.jwt.standard.util;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Ut {
    public static class Json {

        private static final ObjectMapper objectMapper = new ObjectMapper();

        public static String toString(Object obj) {
            try {
                return objectMapper.writeValueAsString(obj);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
