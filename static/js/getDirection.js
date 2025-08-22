function getDirection (delta){
    const UP = 1;
    const DOWN = -1;

    if (!delta){
        clientFlash("Sorry, an error occurred", "danger");
        console.error("Delta not correctly provided in getDirection");
    }

    let direction = 0;

    if (delta > 0){
        direction = UP;
    }else if(delta < 0){
        direction = DOWN;
    }else{
        clientFlash("How... How are you scrolling like that?????", "danger");
    }

    return direction;

}

