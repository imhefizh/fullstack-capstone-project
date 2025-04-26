import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {urlConfig} from '../../config';

function MainPage() {
    const [gifts, setGifts] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        // Task 1: Write async fetch operation
        // Write your code below this line
        async function fetchOp() {
            try {
                let url = `${urlConfig.backendUrl}/api/gifts`;
                const fetchedData = await fetch(url);
                if (!fetchedData.ok) {
                    throw new Error(`HTTP error: ${fetchedData.status}`)
                }
                const data = await fetchedData.json();
                setGifts(data);
            } catch (err) {
                console.log('Fetch error: ' + err.message);
            }
        }

        fetchOp()
    }, []);

    // Task 2: Navigate to details page
    const goToDetailsPage = (productId) => {
        // Write your code below this line
           navigate(`/app/product/${productId}`);
      };

    // Task 3: Format timestamp
    const formatDate = (timestamp) => {
        // Write your code below this line
        const date = new Date(timestamp * 1000);
        return date.toLocaleDateString('default', {month: 'long', day: 'numeric', year: 'numeric'})
      };

    const getConditionClass = (condition) => {
        return condition === "New" ? "list-group-item-success" : "list-group-item-warning";
    };

    return (
        <div className="container mt-5">
            <div className="row">
                {gifts.map((gift) => (
                    <div key={gift.id} className="col-md-4 mb-4">
                        <div className="card product-card">

                            {/* // Task 4: Display gift image or placeholder */}
                            {/* // Write your code below this line */}
                            <div>
                                {gift.image ? ( <img src={gift.image} alt={gift.name} className="card-img-top" />) : (<div className="no-image-available">No Image Available
                                </div>
                                )}
                            </div>
                            <div className="card-body">

                                {/* // Task 5: Display gift image or placeholder */}
                                {/* // Write your code below this line */}
                                <h5 className='card-title'>{gift.name}</h5>
                                <p className={`card-text ${getConditionClass(gift.condition)}`}>
                                {gift.condition}
                                </p>

                                {/* // Task 6: Display gift image or placeholder */}
                                {/* // Write your code below this line */}
                                <p className="card-text">{formatDate(gift.date_added)}</p>

                                <button onClick={() => goToDetailsPage(gift.id)} className="btn btn-primary">
                                    View Details
                                </button>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default MainPage;
