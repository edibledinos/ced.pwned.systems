$.fn.rotate = function(start, stop) {
    return this.each(function() {
        var elem = $(this);
        $({rotate: start}).animate({rotate: stop}, {
            step: function(state) {
                elem.css('transform', 'rotate(' + state + 'deg)');
            }
        });
    });
};


(function ($, root, undefined) {
    $(function () {
        'use strict';

        // DOM ready, take it away

        $('.menu-button').click(function() {
            var elem=$(this), aside = $('aside');
            if(aside.hasClass('collapsed')) {
                elem.rotate(0, 180);
                aside.hide().removeClass('collapsed').show(400);
            } else {
                elem.rotate(180, 360);
                aside.hide(400, function() {
                    aside.addClass('collapsed').css('display', '');
                });
            }
        });

        $(document).mousemove(function(event) {
            var offset = 100 - (event.pageX / $(window).width()) * 100;
            $('.img-front').css('background-position-x', '-' + (offset / 10) + 'px');
            $('.img-middle').css('background-position-x', '-' + (offset / 15) + 'px');
        });

        if($('aside>section#category').length == 0) {
            $('aside').append(
                $('<section>').attr('id', 'jargon').append(
                    $('<header>').append(
                        $('<a>').attr('href', 'http://shinytoylabs.com/jargon/').text('!')
                    ),
                    $('<p>').text(jargon.generate())
                )
            );
        }
    });
})(jQuery, this);
