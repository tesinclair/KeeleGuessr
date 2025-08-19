/**
* @param obj NOT the object you are scrolling on, but the text child to be changed
* @param targets an array of target strings to scroll between
* @param numTargets the number of targets (not the index of the last target)
**/
function scrollObject(obj, direction, pos, targets, numTargets){
    // first just change the text
    if (direction == UP){
        pos--;
        pos += numTargets; // account for negative pos
        pos = pos % numTargets;
    }
    if (direction == DOWN){
        pos++;
        pos = pos % numTargets;
    }

    if (pos < 0){
        pos = 0;
        console.error("I made a mistake...");
    }

    obj.innerHTML = targets[pos];

    return [pos, targets[pos]];
}

