import express from 'express'
import mongoose from 'mongoose'
import User from '../models/user'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

export function middlewareTokenValidation(req, res, next) {
  var token = req.headers['x-access-token'];

  if (token) {
    jwt.verify(token, process.env.MONGO_SECRET, (err, decoded) => {      
      if (err) {
        return res.json({ success: false, message: 'falha na autenticação do token.' });    
      } else {
        req.decoded = decoded;    
        next();
      }
    });
  } else {
    return res.status(403).send({ 
        success: false, 
        message: 'Nenhum token fornecido.' 
    });
  }
}

export function signUp(req, res) {
	if(req.body.username == null){
		res.json({ success: false, message: 'Falha no Cadastro. Usuário deve ser fornecido.' })
		return
	} 
	
	if(req.body.password == null){
		res.json({ success: false, message: 'Falha no Cadastro. Senha deve ser fornecida.' })
		return
	}

  const saltRounds = 10;//tempo pra gerar hash "bcrypt"
  bcrypt.hash(req.body.password, saltRounds).then((hash) => {
		var user = new User({ 
      username: req.body.username,
	    password: hash
	  });

	  user.save((err) => {
	    if (err) {
	    	if(err.code == 11000){
          res.json({ success: false, message: 'Falha no Cadastro. Usuário já existe.' })
	    	} else {
					throw err	    		
	    	}
	    } else {
	    	res.json({ success: true, message: 'Usuário Cadastrado com sucesso!' })
	    }
	    
	  });
	});
}

export function authenticate(req, res) {
  User.findOne({
    username: req.body.username
  }, (err, user) => {

    if (err) throw err;

    if (!user) {
      res.json({ 
      	success: false, 
      	message: 'Falha na autenticação. Usuário não encontrado.' 
      });
    } else if (user) {

      bcrypt.compare(req.body.password, user.password, (err, bCryptResponse) => {
      	if(bCryptResponse){
	      	var token = jwt.sign(user, process.env.MONGO_SECRET, {
	          expiresIn : 60*60*24 //24h 
	        });

	        res.json({
	          success: true,
            token: token,
            usertype: user.usertype
        	});
      	} else {
      		res.json({
	          success: false,
	          message: 'Senha Incorreta!'
        	});
      	}
        
      });
    }
  });
}

export function validateToken(req, res) {
	var token = req.headers['x-access-token'];
	if(token){
    jwt.verify(token, process.env.MONGO_SECRET, (err, decoded) => {      
      if (err) {
        return res.json({ success: false, message: 'Falha na autenticação do token.' });    
      } else {
        return res.json({ 
	        success: true, 
	        message: 'Token válido foi informado.' 
    		});
      }
    });
	}else{
		return res.status(403).send({ 
        success: false, 
        message: 'Nenhum token válido foi informado.' 
    });
	}
}

export function getAllUsers(req, res) {
	User.find({}, function(err, users) {
    res.json(users);
  });
}

export function getUserById(req, res) {
	if (mongoose.Types.ObjectId.isValid(req.params.userId)){
    
    User.find({_id: req.params.userId}, (err, user) => {
      if (err) throw err;
      return res.json(user);
    });

  } else {
    return res.json({ success: false, message: 'Não foi possível visualizar Usuário. The id provided is an invalid ObjectId.' });
  }
}

export function updateUser(req, res) {
	if (mongoose.Types.ObjectId.isValid(req.params.userId)){
    
    User.update({_id: req.params.userId}, req.body, (err, result) => {
      if (err) throw err;
      return res.json(result);
    });
    
  } else {
    return res.json({ success: false, message: 'Não foi possível atualizar Usuário. The id provided is an invalid ObjectId.' });  
  }
}

export function deleteUser(req, res) {
	if (mongoose.Types.ObjectId.isValid(req.params.userId)){
    
    User.remove({_id: req.params.userId}, (err, result) => {
      if (err) throw err;
      return res.json(result);
    });
    
  } else {
    return res.json({ success: false, message: 'Não foi possível deletar Usuário. The id provided is an invalid ObjectId.' });  
  }
}