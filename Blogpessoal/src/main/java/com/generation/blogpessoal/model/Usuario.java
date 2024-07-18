package com.generation.blogpessoal.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "tb_usuarios")
public class Usuario {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	@NotNull(message = "Nome é obrigatório")
	private String nome;
	
	@NotNull(message = "Usuario é obrigatório")
	@Email(message = "O atributo usuario deve ser um email válido")
	private String usuario;
	
	@NotNull(message = "Senha é obrigatório")
	@Size(min = 7, message = "A senha deve ter no mínimo 7 caracteres")
	private String senha;
	
	@Size(max = 5000, message = "A foto deve ter no máximo 5000 caracteres")
	private String foto;
	
	@OneToMany(fetch = FetchType.LAZY, mappedBy  = "usuario", cascade  = CascadeType.REMOVE)
	@JsonIgnoreProperties({"usuario"})
	private List<Postagem> postagem;

	
	
	public Usuario(long id,String nome, String usuario, String senha,String foto) {
		this.id = id;
		this.nome = nome;
		this.usuario = usuario;
		this.senha = senha;
		this.foto = foto;
	}

	public Usuario() {
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getUsuario() {
		return usuario;
	}

	public void setUsuario(String usuario) {
		this.usuario = usuario;
	}

	public String getSenha() {
		return senha;
	}

	public void setSenha(String senha) {
		this.senha = senha;
	}

	public String getFoto() {
		return foto;
	}

	public void setFoto(String foto) {
		this.foto = foto;
	}

	public List<Postagem> getPostagem() {
		return postagem;
	}

	public void setPostagem(List<Postagem> postagem) {
		this.postagem = postagem;
	}
	

}
