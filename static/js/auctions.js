function filtreaza_status() {
      var option = document.getElementById('status').value;
      var redirectURL;

      if (option === 'closed') {
        window.location.href = '/auctions_with_status_closed';
      } else if (option === 'open') {
        window.location.href = '/auctions_with_status_open';
      }
    }
function filtreaza_pret() {
      var option = document.getElementById('pret_function').value;
      var redirectURL;

      if (option === 'crescator') {
        window.location.href = '/auctions_ordered_ascending_by_current_price';
      } else if (option === 'descrescator') {
        window.location.href = '/auctions_ordered_descending_by_current_price';
      }
    }

function refresh() {
        window.location.href = '/auctions'; // Replace with your desired URL
        }