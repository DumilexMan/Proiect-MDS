function filtreaza_pret() {
      var option = document.getElementById('pret_function').value;
      var redirectURL;

      if (option === 'crescator') {
        window.location.href = '/posts_filter_ascending_by_price';
      } else if (option === 'descrescator') {
        window.location.href = '/posts_filter_descending_by_price';
      }
    }

function refresh() {
        window.location.href = '/posts'; // Replace with your desired URL
        }

