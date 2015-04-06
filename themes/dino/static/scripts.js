(function ($, root, undefined) {
    $(function () {
        'use strict';

        // DOM ready, take it away

        $('.menu-button').click(function() {
            $('aside').toggleClass('collapsed');
        });

        $(document).mousemove(function(event) {
            var offset = 100 - (event.pageX / $(window).width()) * 100;
            $('.img-front').css('background-position-x', '-' + (offset / 10) + 'px');
            $('.img-middle').css('background-position-x', '-' + (offset / 15) + 'px');
        });
    });
})(jQuery, this);
