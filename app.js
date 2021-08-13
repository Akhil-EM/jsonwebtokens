require('dotenv').config();
const express=require('express');
const jwt=require('jsonwebtoken');
const app=express();
app.use(express.json());
const port=process.env.PORT || 2000;

const posts=[{userName:"amal",tittle:"amal's post"},
             {userName:"akhil",tittle:"akhil's post"}]

let refreshTokens=[];
app.get('/posts',authenticateToken,(req,res)=>{
    res.json({posts:posts.filter(post=>post.userName === req.body.user.name)});
})

app.post('/token',(req,res)=>{
    const refreshToken=req.body.token;
    
    if(refreshToken == null)return res.sendStatus(401);

    if(!refreshTokens.includes(refreshToken))return res.sendStatus(403);

    jwt.verify(refreshToken,process.env.REFRESH_TOKEN,(error,user)=>{
        if(error) return res.sendStatus(403);
        const accessToken=generateAccessToken({name:user.name});
        res.json({accessToken:accessToken});
    })
})


app.post('/login',(req,res)=>{
    // authenticate user
    const userName=req.body.userName;
    const user={name:userName};

    const accessToken=generateAccessToken(user);
    const refreshToken=jwt.sign(user,process.env.REFRESH_TOKEN);
    refreshTokens.push(refreshToken);
    res.json({accessToken:accessToken,refreshToken:refreshToken});
})

app.delete('/logout',(req,res)=>{
    console.log(req.body)
    console.log(refreshTokens)
    refreshTokens=refreshTokens.filter(token=>token !== req.body.token);
    res.send('successfully log out..!!');
})

function generateAccessToken(user){
    return jwt.sign(user,process.env.ACCESS_TOKEN,{expiresIn:'60s'});
}

function authenticateToken(req,res,next){
    const authHeader=req.headers['authorization'];
    const token=authHeader && authHeader.split(" ")[1]; //either undefined or the token
    if(token==null) return res.json({message:'no token found'});
    jwt.verify(token,process.env.ACCESS_TOKEN,(error,user)=>{
        if(error){
           return  res.json({message:'invalid token'});
        }
        req.body.user=user;
        next();
    })
}

app.listen(port,()=>console.log(`\nApplication running on ${port}`))