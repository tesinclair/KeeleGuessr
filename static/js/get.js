async function getInfo(url){
    try {
        const res = await fetch(url);
        const data = await res.json();

        if (!res.ok){
            console.error("Bad request: ", res)
        }

        return data;
    } catch (err){
        console.error("Network Error: ", err);
    }
}

