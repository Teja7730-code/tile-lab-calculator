import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";


const STORE_NAME =
    "ceramic-lab-data";


const DATABASE_KEY =
    "database";


const USERNAME =
    process.env.LAB_USERNAME ||
    "admin";


const PASSWORD =
    process.env.LAB_PASSWORD ||
    "1234";


/* =========================================================
   RESPONSE
========================================================= */

function json(
    data,
    status=200
){

    return new Response(
        JSON.stringify(data),
        {
            status,

            headers:{
                "Content-Type":
                    "application/json",

                "Cache-Control":
                    "no-store"
            }
        }
    );

}


/* =========================================================
   TOKEN
========================================================= */

function createToken(){

    const payload = {

        username:USERNAME,

        issuedAt:Date.now(),

        nonce:
            crypto.randomUUID()

    };


    return Buffer
        .from(
            JSON.stringify(payload)
        )
        .toString("base64url");

}


function validateToken(
    token
){

    if(!token)
        return false;


    try{

        const payload =
            JSON.parse(
                Buffer
                    .from(
                        token,
                        "base64url"
                    )
                    .toString("utf8")
            );


        if(
            !payload ||
            payload.username !==
                USERNAME
        ){

            return false;

        }


        /*
            Session validity:
            30 days.
        */

        const age =
            Date.now() -
            Number(
                payload.issuedAt
            );


        return (
            Number.isFinite(age) &&
            age >= 0 &&
            age <
                30 *
                24 *
                60 *
                60 *
                1000
        );

    }catch{

        return false;

    }

}


/* =========================================================
   STORE
========================================================= */

function store(){

    /*
        Site-wide store.

        This survives new deploys and is shared
        by the site's Functions.
    */

    return getStore({

        name:STORE_NAME,

        consistency:"strong"

    });

}


/* =========================================================
   FUNCTION
========================================================= */

export default async function handler(
    request
){

    if(
        request.method !==
        "POST"
    ){

        return json(
            {
                error:
                    "POST required"
            },
            405
        );

    }


    let body;


    try{

        body =
            await request.json();

    }catch{

        return json(
            {
                error:
                    "Invalid JSON"
            },
            400
        );

    }


    /* =====================================================
       LOGIN
    ===================================================== */

    if(
        body.action ===
        "login"
    ){

        const username =
            String(
                body.username ||
                ""
            );


        const password =
            String(
                body.password ||
                ""
            );


        if(
            username !==
                USERNAME ||
            password !==
                PASSWORD
        ){

            return json(
                {
                    error:
                        "Invalid username or password"
                },
                401
            );

        }


        return json({

            authenticated:true,

            token:
                createToken()

        });

    }


    /* =====================================================
       AUTH CHECK
    ===================================================== */

    if(
        !validateToken(
            body.token
        )
    ){

        return json(
            {
                error:
                    "Session expired or invalid"
            },
            401
        );

    }


    const db =
        store();


    /* =====================================================
       GET
    ===================================================== */

    if(
        body.action ===
        "get"
    ){

        try{

            const data =
                await db.get(
                    DATABASE_KEY,
                    {
                        type:"json",

                        consistency:
                            "strong"
                    }
                );


            return json({

                data:
                    data || null

            });

        }catch(error){

            console.error(
                "DATABASE GET:",
                error
            );


            return json(
                {
                    error:
                        "Cloud database read failed"
                },
                500
            );

        }

    }


    /* =====================================================
       SAVE
    ===================================================== */

    if(
        body.action ===
        "save"
    ){

        if(
            !body.data ||
            typeof body.data !==
                "object"
        ){

            return json(
                {
                    error:
                        "Database payload missing"
                },
                400
            );

        }


        try{

            /*
                Complete database replacement.

                Netlify Blobs setJSON overwrites
                the existing value for this key.
            */

            const result =
                await db.setJSON(
                    DATABASE_KEY,
                    body.data
                );


            /*
                Strongly-consistent verification.
            */

            const verify =
                await db.get(
                    DATABASE_KEY,
                    {
                        type:"json",

                        consistency:
                            "strong"
                    }
                );


            if(!verify){

                throw new Error(
                    "Write verification failed"
                );

            }


            return json({

                saved:true,

                verified:true,

                modified:
                    result.modified ===
                    true

            });

        }catch(error){

            console.error(
                "DATABASE SAVE:",
                error
            );


            return json(
                {
                    error:
                        "Cloud database save failed"
                },
                500
            );

        }

    }


    return json(
        {
            error:
                "Unknown action"
        },
        400
    );

}