(function ($, root, undefined) {
    $(function () {
        'use strict';

        // DOM ready, take it away

        $('.menu-button').click(function() {
            $('aside').toggleClass('collapsed');
        });
    });
})(jQuery, this);
