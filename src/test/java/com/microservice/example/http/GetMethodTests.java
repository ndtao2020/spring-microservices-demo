package com.microservice.example.http;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import jodd.http.HttpRequest;
import jodd.http.HttpResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.routing.RoutingSupport;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.eclipse.jetty.client.ContentResponse;
import org.eclipse.jetty.client.HttpClient;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class GetMethodTests {

    public static final String API_URL = "https://jsonplaceholder.typicode.com/posts";

    //    @Test
    void java() throws IOException {
        URL url = new URL(API_URL);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        try (final InputStream is = con.getInputStream()) {
            JSONArray jsonArray = JSON.parseArray(is);
            assertNotNull(jsonArray);
            for (Object obj : jsonArray) {
                JSONObject jsonObject = (JSONObject) obj;
                assertEquals(Integer.class, jsonObject.get("userId").getClass());
            }
        }
    }

    //    @Test
    void apacheHttpClient() throws IOException {
        HttpGet httpGet = new HttpGet(API_URL);
        try (CloseableHttpClient httpclient = HttpClients.createDefault();
             CloseableHttpResponse response = httpclient.execute(httpGet);
             HttpEntity entity = response.getEntity()) {
            try (final InputStream is = entity.getContent()) {
                JSONArray jsonArray = JSON.parseArray(is);
                assertNotNull(jsonArray);
                for (Object obj : jsonArray) {
                    JSONObject jsonObject = (JSONObject) obj;
                    assertEquals(Integer.class, jsonObject.get("userId").getClass());
                }
            }
        }
    }

    //    @Test
    void apacheHttpClientHandle() throws IOException, HttpException {
        HttpGet httpGet = new HttpGet(API_URL);
        HttpHost httpHost = RoutingSupport.determineHost(httpGet);
        HttpClientResponseHandler<JSONArray> responseHandler = response -> {
            final HttpEntity entity = response.getEntity();
            try (final InputStream is = entity.getContent()) {
                return JSON.parseArray(is);
            }
        };
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            JSONArray jsonArray = httpclient.execute(httpHost, httpGet, null, responseHandler);
            assertNotNull(jsonArray);
            for (Object obj : jsonArray) {
                JSONObject jsonObject = (JSONObject) obj;
                assertEquals(Integer.class, jsonObject.get("userId").getClass());
            }
        }
    }

    //    @Test
    void okhttp() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder().url(API_URL).build();
        try (Response response = client.newCall(request).execute();
             ResponseBody responseBody = response.body()) {
            JSONArray jsonArray = JSON.parseArray(responseBody.bytes());
            assertNotNull(jsonArray);
            for (Object obj : jsonArray) {
                JSONObject jsonObject = (JSONObject) obj;
                assertEquals(Integer.class, jsonObject.get("userId").getClass());
            }
        }
    }

    //    @Test
    void jetty() throws Exception {
        HttpClient client = new HttpClient();
        client.start();
        try {
            ContentResponse res = client.GET(API_URL);
            JSONArray jsonArray = JSON.parseArray(res.getContent());
            assertNotNull(jsonArray);
            for (Object obj : jsonArray) {
                JSONObject jsonObject = (JSONObject) obj;
                assertEquals(Integer.class, jsonObject.get("userId").getClass());
            }
        } finally {
            client.stop();
        }
    }

    //    @Test
    void jodd() {
        HttpResponse response = HttpRequest.get(API_URL).send();
        JSONArray jsonArray = JSON.parseArray(response.bodyBytes());
        assertNotNull(jsonArray);
        for (Object obj : jsonArray) {
            JSONObject jsonObject = (JSONObject) obj;
            assertEquals(Integer.class, jsonObject.get("userId").getClass());
        }
    }
}
