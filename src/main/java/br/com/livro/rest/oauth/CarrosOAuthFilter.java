package br.com.livro.rest.oauth;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glassfish.jersey.client.oauth1.AccessToken;
import org.glassfish.jersey.client.oauth1.ConsumerCredentials;
import org.glassfish.jersey.client.oauth1.OAuth1AuthorizationFlow;
import org.glassfish.jersey.client.oauth1.OAuth1Builder.FlowBuilder;
import org.glassfish.jersey.client.oauth1.OAuth1ClientSupport;

import br.com.livro.rest.MyApplication;
import br.com.livro.util.ServletUtil;

@WebFilter("/rest/carrosv2/*")
public class CarrosOAuthFilter implements Filter {

	// Cria o fluxo de autoriza��o
	public OAuth1AuthorizationFlow getAuthorizationFlow(HttpServletRequest request, String callbackUri) {
		final ConsumerCredentials consumerCredentials = new ConsumerCredentials(MyApplication.CONSUMER_KEY,
				MyApplication.CONSUMER_SECRET);
		final FlowBuilder builder = OAuth1ClientSupport.builder(consumerCredentials).authorizationFlow(
				"http://localhost:8080/carros/rest/requestToken", "http://localhost:8080/carros/rest/accessToken",
				"http://localhost:8080/carros/rest/authorize");
		if (callbackUri != null) {
			builder.callbackUri(callbackUri);
		}
		OAuth1AuthorizationFlow authFlow = builder.build();
		request.getSession().setAttribute("authFlow", authFlow);
		return authFlow;
	}

	public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
			throws IOException, ServletException {

		final HttpServletRequest req = (HttpServletRequest) request;
		final HttpServletResponse resp = (HttpServletResponse) response;
		AccessToken accessToken = (AccessToken) req.getSession().getAttribute("accessToken");

		if (accessToken == null) {
			String oauth_verifier = req.getParameter("oauth_verifier");
			String oauth_token = req.getParameter("oauth_token");
			if (oauth_verifier != null && oauth_token != null) {
				// Voltou do aplicacao, verifica o c�digo
				verify(req, oauth_verifier);
			} else {
				// Precisa redirecionar para o Twitter
				auth(req, resp);
				return;
			}
		}
		// Continua a requisi��o
		chain.doFilter(req, resp);
	}

	private void verify(final HttpServletRequest req, final String oauth_verifier) {
		AccessToken accessToken;
		OAuth1AuthorizationFlow authFlow = (OAuth1AuthorizationFlow) req.getSession().getAttribute("authFlow");
		if (authFlow != null) {
			accessToken = authFlow.finish(oauth_verifier);
			req.getSession().setAttribute("accessToken", accessToken);
		}
	}

	private void auth(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
		String url = ServletUtil.getRequestURL(req);
		OAuth1AuthorizationFlow authFlow = getAuthorizationFlow(req, url);
		String authorizationUri = authFlow.start();
		resp.sendRedirect(authorizationUri);
	}
	
	@Override
	public void init(final FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void destroy() {
	}

}
