package com.rremiao.security.e3;

import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.rremiao.security.e3.steps.StepOne;

@SpringBootApplication
public class E3Application implements CommandLineRunner{

	@Autowired
	private StepOne stepOne;

	public static void main(String[] args) {
		SpringApplication.run(E3Application.class, args);
	}

	@Override
	public void run(String ...args) throws NoSuchAlgorithmException {
		stepOne.run();
	}

}
