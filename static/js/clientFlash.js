function clientFlash(text, level){
    const clientFlashElement = document.getElementById('flash-client-div');
    const clientFlashText = document.getElementById('flash-client-msg-span');

    clientFlashElement.classList.add(level);
    clientFlashText.classList.add(level);
    clientFlashText.innerHTML = text;

    clientFlashElement.style.right = `${clientFlashElement.offsetWidth}px`;
    clientFlashElement.classList.remove('hidden');
    
    requestAnimationFrame(()=>{
        clientFlashElement.style.right = "3em";
    });
}

