function getDirection (wheelDelta){
    if (!wheelDelta){
        clientFlash("Sorry, an error occurred", "danger");
    }
    let direction = 0;
    if (wheelDelta > 0){
        direction = UP;
    }else if(wheelDelta < 0){
        direction = DOWN;
    }else{
        clientFlash("How... How are you scrolling like that?????", "danger");
    }

    return direction;

}

