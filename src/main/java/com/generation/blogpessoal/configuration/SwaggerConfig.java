package com.generation.blogpessoal.configuration;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;

@Configuration
public class SwaggerConfig {

	@Bean
	OpenAPI springBlogPessoalOpenAPI() {
		return new OpenAPI().info(new Info()
				.title("Projeto blog Pessoal")
				.description("Projeto Blog Pessoal - Generation Brasil")
				.version("v0.0.1")
				.license(new License()
						.name("Geration Brasil")
						.url("https://brasil.geration.org/"))
				.contact(new Contact()
						.name("Édipo Reis")
						.url("https://github.com/EdiporTorres")
						.email("ediporeiss@gmail.com")))
				.externalDocs(new ExternalDocumentation()
						.description("GitHUb")
						.url("https://github.com/EdiporTorres"));
	}
	
	@Bean
	OpenApiCustomizer customerGlobalHeaderOpenApiCumtomiser() {
		return openApi ->{
			openApi.getPaths().values().forEach(pathitem -> pathitem.readOperations()
					.forEach(operation -> {
						ApiResponses apiResponses = operation.getResponses();
						apiResponses.addApiResponse("200", createApiResponse("Sucesso"));
						apiResponses.addApiResponse("201", createApiResponse("Criado"));
						apiResponses.addApiResponse("204", createApiResponse("Excluido"));
						apiResponses.addApiResponse("400", createApiResponse("Requisição Inválida"));
						apiResponses.addApiResponse("401", createApiResponse("Não Autorizado"));
						apiResponses.addApiResponse("403", createApiResponse("Proibido"));
						apiResponses.addApiResponse("404", createApiResponse("Não Encontrado"));
						apiResponses.addApiResponse("500", createApiResponse("Erro Interno"));
					}));
		};
	}
	
	private ApiResponse createApiResponse(String message) {
		return new ApiResponse().description(message);
	}
	
	
	
	
	
	
}
