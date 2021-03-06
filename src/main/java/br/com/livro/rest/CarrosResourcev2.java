package br.com.livro.rest;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.oauth1.AccessToken;
import org.glassfish.jersey.client.oauth1.ConsumerCredentials;
import org.glassfish.jersey.client.oauth1.OAuth1ClientSupport;

@Path("/carrosv2")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class CarrosResourcev2 {
	
	private static final String URL = "http://localhost:8080/carros";
	
	@Context
	private HttpServletRequest req;
	
	@GET
	public Response getCarros() {
		final Client client = getClient();
		final Response r = Response.ok(client.target(URL).path("/rest/carros")
				.request(MediaType.APPLICATION_JSON)
				.get(String.class)).build();
		return r;
	}
	
	@GET
	@Path("/userInfo")
	@Produces(MediaType.TEXT_PLAIN + ";charset=utf-8")
	public Response userInfo() {
		final Client client = getClient();
		final Response r = Response.ok(client.target(URL).path("/rest/userInfo")
				.request(MediaType.TEXT_PLAIN)
				.get(String.class)).build();
		return r;
	}

	private Client getClient() {
		final AccessToken accessToken = (AccessToken) req.getSession().getAttribute("accessToken");
		final String consumerKey = MyApplication.CONSUMER_KEY;
		final String consumerSecret = MyApplication.CONSUMER_SECRET;
		final ConsumerCredentials credentials = new ConsumerCredentials(consumerKey, consumerSecret);
		final Feature feature = OAuth1ClientSupport.builder(credentials).feature()
				.accessToken(accessToken).build();
		final Client client = ClientBuilder.newClient().register(feature)
				.register(GsonMessageBodyHandler.class);
		return client;
	}
}
