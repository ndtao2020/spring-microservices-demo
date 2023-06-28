package com.microservice.benchmark.http;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
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

//@State(Scope.Benchmark)
//@BenchmarkMode(Mode.AverageTime)
//@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class GetMethod {

    public static final String API_URL = "https://jsonplaceholder.typicode.com/posts";

    // @Benchmark
    public JSONArray java() throws IOException {
        final URL url = new URL(API_URL);
        final HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        try (final InputStream is = con.getInputStream()) {
            return JSON.parseArray(is);
        }
    }

    // @Benchmark
    public JSONArray apacheHttp() throws IOException {
        HttpGet httpGet = new HttpGet(API_URL);
        try (final CloseableHttpClient httpclient = HttpClients.createDefault();
             final CloseableHttpResponse response = httpclient.execute(httpGet);
             final HttpEntity entity = response.getEntity();
             final InputStream is = entity.getContent()) {
            return JSON.parseArray(is);
        }
    }

    // @Benchmark
    public JSONArray apacheHttpHandle() throws IOException, HttpException {
        HttpGet httpGet = new HttpGet(API_URL);
        HttpHost httpHost = RoutingSupport.determineHost(httpGet);
        HttpClientResponseHandler<JSONArray> responseHandler = response -> {
            try (final HttpEntity entity = response.getEntity();
                 final InputStream is = entity.getContent()) {
                return JSON.parseArray(is);
            }
        };
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            return httpclient.execute(httpHost, httpGet, null, responseHandler);
        }
    }

    // @Benchmark
    public JSONArray okhttp() throws IOException {
        final OkHttpClient client = new OkHttpClient();
        final Request request = new Request.Builder().url(API_URL).build();
        try (Response response = client.newCall(request).execute(); ResponseBody responseBody = response.body()) {
            return JSON.parseArray(responseBody.bytes());
        }
    }

    // @Benchmark
    public JSONArray jetty() throws Exception {
        final HttpClient client = new HttpClient();
        client.start();
        JSONArray jsonArray;
        try {
            final ContentResponse res = client.GET(API_URL);
            jsonArray = JSON.parseArray(res.getContent());
        } finally {
            client.stop();
        }
        return jsonArray;
    }

    // @Benchmark
    public JSONArray jodd() {
        final HttpResponse response = HttpRequest.get(API_URL).send();
        return JSON.parseArray(response.bodyBytes());
    }
}
