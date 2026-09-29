package ru.tsl.auth.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

/** Внутренняя обёртка над Jackson: JSON-объект как Map. */
final class Json {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<Map<String, Object>>() {};

    private Json() {}

    static Map<String, Object> parseObject(byte[] bytes) throws IOException {
        return MAPPER.readValue(bytes, MAP);
    }

    static Map<String, Object> parseObject(String text) throws IOException {
        return MAPPER.readValue(text, MAP);
    }

    static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
