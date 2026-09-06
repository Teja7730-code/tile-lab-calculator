import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const STORE_NAME = "ceramic-lab-data";
const DATABASE_KEY = "database";

const USERNAME =
  process.env.LAB_USERNAME || "admin";

const PASSWORD =
  process.env.LAB_PASSWORD || "1234";


const headers={
  "content-type":
    "application/json; charset=utf-8",

  "cache-control":
    "no-store"
};


function response(
  body,
  status=200
){

  return new Response(
    JSON.stringify(body),
    {
      status,
      headers
    }
  );
}


/* =========================================================
   SESSION TOKEN
   ========================================================= */

function issueToken(username){

  const payload=
    Buffer
      .from(
        JSON.stringify({
          u:username,
          t:Date.now()
        })
      )
      .toString("base64url");


  const signature=
    crypto
      .createHash("sha256")
      .update(
        payload+
        PASSWORD
      )
      .digest("base64url");


  return payload+"."+signature;
}


function validToken(token){

  if(!token)return false;

  try{

    const parts=
      token.split(".");

    if(parts.length!==2)
      return false;

    const payload=
      parts[0];

    const signature=
      parts[1];


    const expected=
      crypto
        .createHash("sha256")
        .update(
          payload+
          PASSWORD
        )
        .digest("base64url");


    if(
      signature.length!==expected.length
    ){
      return false;
    }


    if(
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ){
      return false;
    }


    const data=
      JSON.parse(
        Buffer
          .from(
            payload,
            "base64url"
          )
          .toString()
      );


    return(
      data.u===USERNAME &&
      Date.now()-data.t<
        30*
        24*
        60*
        60*
        1000
    );

  }catch{

    return false;
  }
}


/* =========================================================
   FUNCTION
   ========================================================= */

export default async function(request){

  if(request.method!=="POST"){

    return response(
      {
        ok:false,
        error:"POST only"
      },
      405
    );
  }


  try{

    const body=
      await request.json();


    const action=
      body.action;


    /* LOGIN */

    if(action==="login"){

      if(
        body.username!==USERNAME ||
        body.password!==PASSWORD
      ){

        return response(
          {
            ok:false,
            error:
              "Invalid username or password"
          },
          401
        );
      }


      return response({
        ok:true,
        token:
          issueToken(
            USERNAME
          )
      });
    }


    /* AUTH */

    if(
      !validToken(
        body.token
      )
    ){

      return response(
        {
          ok:false,
          error:"Session expired"
        },
        401
      );
    }


    /* STORE */

    const store=
      getStore({
        name:STORE_NAME,
        consistency:"strong"
      });


    /* GET */

    if(action==="get"){

      const data=
        await store.get(
          DATABASE_KEY,
          {
            type:"json"
          }
        );


      return response({
        ok:true,
        data:
          data ||
          {
            materials:[],
            targets:[]
          }
      });
    }


    /* SAVE */

    if(action==="save"){

      const data=
        body.data ||
        {
          materials:[],
          targets:[]
        };


      await store.setJSON(
        DATABASE_KEY,
        data
      );


      const verify=
        await store.get(
          DATABASE_KEY,
          {
            type:"json"
          }
        );


      return response({
        ok:true,
        saved:true,
        verified:
          !!verify
      });
    }


    return response(
      {
        ok:false,
        error:"Unknown action"
      },
      400
    );


  }catch(error){

    console.error(error);

    return response(
      {
        ok:false,
        error:
          error.message ||
          "Server error"
      },
      500
    );
  }
}