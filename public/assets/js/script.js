document.addEventListener("DOMContentLoaded", function () {
    let carouselContent = document.getElementById("carousel-content");

    fetch("/assets/src home/files.json")
        .then(response => response.json())
        .then(data => {
            let first = true;

            data.files.forEach(file => {
                let carouselItem = document.createElement("div");
                carouselItem.classList.add("carousel-item");
                if (first) {
                    carouselItem.classList.add("active");
                    first = false;
                }

                if (file.type === "image") {
                    let img = document.createElement("img");
                    img.src = file.src;
                    img.alt = file.alt;
                    img.classList.add("d-block", "mx-auto");
                    img.style.maxHeight = "500px";
                    img.style.objectFit = "contain";
                    carouselItem.appendChild(img);
                } else if (file.type === "video") {
                    let video = document.createElement("video");
                    video.classList.add("d-block", "mx-auto");
                    video.style.maxHeight = "500px";
                    video.style.objectFit = "contain";
                    video.controls = true;

                    let source = document.createElement("source");
                    source.src = file.src;
                    source.type = "video/mp4";

                    video.appendChild(source);
                    carouselItem.appendChild(video);
                }

                carouselContent.appendChild(carouselItem);
            });
        })
        .catch(error => console.error("Erreur lors du chargement des fichiers :", error));
});


document.addEventListener("DOMContentLoaded", function () {
    let progressBar = document.querySelector(".progress-bar");
    let carousel = document.querySelector("#carousel");
    let intervalTime = 7000;
    let progressInterval;

    function startProgress() {
        progressBar.style.transition = "none";
        progressBar.style.width = "0%";

        void progressBar.offsetWidth; 

        setTimeout(() => {
            progressBar.style.transition = `width ${intervalTime}ms linear`;
            progressBar.style.width = "100%";

            progressInterval = setTimeout(() => {
                let carouselInstance = new bootstrap.Carousel(carousel);
                carouselInstance.next();
                resetProgress();
            }, intervalTime);
        }, 50);
    }

    function resetProgress() {
        clearTimeout(progressInterval);
        progressBar.style.transition = "none";
        progressBar.style.width = "0%";


        void progressBar.offsetWidth; 

        setTimeout(() => {
            progressBar.style.transition = `width ${intervalTime}ms linear`;
            progressBar.style.width = "100%";

            progressInterval = setTimeout(() => {
                let carouselInstance = new bootstrap.Carousel(carousel);
                carouselInstance.next();
                resetProgress();
            }, intervalTime);
        }, 50);
    }

    document.querySelector(".carousel-control-prev").addEventListener("click", function () {
        let carouselInstance = new bootstrap.Carousel(carousel);
        carouselInstance.prev();
        resetProgress();
    });

    document.querySelector(".carousel-control-next").addEventListener("click", function () {
        let carouselInstance = new bootstrap.Carousel(carousel);
        carouselInstance.next();
        resetProgress();
    });

    startProgress();
});
